/**
 * Source-code crypto scanner.
 *
 * A fast first-pass regex sweep (no TS AST) over a local directory, flagging
 * weak `node:crypto` usage, JSON Web Token algorithms, hardcoded private keys
 * and PEM-encoded public keys. The github-clone helper lets the CLI scan a
 * remote repo by URL.
 */
import { execFile } from "node:child_process";
import { mkdtemp, readdir, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import type { Confidence, Finding, Severity } from "../report";
import { REFS } from "../crypto";
import { isJsTsFile, jwtAssessment, scanJsAst } from "./source-ast";
import type { PushFinding, ScanJsResult } from "./source-ast";

const execFileAsync = promisify(execFile);

export interface SourceScanOptions {
  /** Directories skipped during the walk. */
  ignoreDirs?: string[];
  /** Files larger than this (bytes) are skipped. */
  maxFileBytes?: number;
  /** Maximum number of files to scan before stopping (bounds a hostile repo). */
  maxFiles?: number;
  /** Maximum total bytes to read before stopping. */
  maxTotalBytes?: number;
}

interface WalkBudget {
  files: number;
  bytes: number;
  truncated: boolean;
  /** Paths the walk could not read; reported so a coverage gap is never silent. */
  skipped: { count: number; names: string[] };
}

/** How many skipped paths are named in the coverage finding; the rest are counted only. */
const MAX_SKIPPED_NAMED = 10;

/** Record an unreadable path, keeping only a bounded sample of the names. */
function recordSkipped(budget: WalkBudget, relPath: string): void {
  budget.skipped.count += 1;
  if (budget.skipped.names.length < MAX_SKIPPED_NAMED) budget.skipped.names.push(relPath);
}

const DEFAULT_MAX_FILES = 25_000;
const DEFAULT_MAX_TOTAL_BYTES = 300_000_000;

const DEFAULT_IGNORE_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "coverage",
  ".next",
  "out",
  "vendor",
  ".turbo",
]);

const DEFAULT_MAX_FILE_BYTES = 2_000_000;

const WEAK_HASH = /\bcreateHash\s*\(\s*["'`](md5|sha-?1)["'`]/gi;
const WEAK_CIPHER =
  /\bcreate(?:Cipher|Decipher)(?:iv)?\s*\(\s*["'`]([a-z0-9_-]*(?:des|rc4|rc2)[a-z0-9_-]*)["'`]/gi;
const JWT_ALG = /["'`](HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|EdDSA|none)["'`]/g;
const JWT_USAGE = /jsonwebtoken|\bjwt\s*\.\s*(?:sign|verify|decode)/i;
/**
 * A private-key block is only flagged when it has a real base64 body between the
 * BEGIN/END markers. A bare header or a `...`-elided snippet (as in READMEs and
 * docs) does not match, that alone kills the most common false critical.
 *
 * The optional RFC 1421 header block (`Proc-Type: 4,ENCRYPTED` / `DEK-Info: …`)
 * must be skipped explicitly: passphrase-protected keys are the most common
 * committed-key form in the wild, precisely because developers believe the
 * passphrase makes committing them safe.
 */
const PRIVATE_KEY =
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----[\r\n]+(?:[A-Za-z][\w-]*:[^\r\n]*[\r\n]+)*[\r\n]*[A-Za-z0-9+/=\r\n]{40,}-----END/g;
const PUBLIC_KEY = /-----BEGIN (?:RSA )?PUBLIC KEY-----/g;

/**
 * Where a match was found. A weak primitive in a real source file is a live code
 * path; the same string in documentation or a test fixture is usually an
 * example, so we lower its severity and mark the finding low-confidence rather
 * than crying wolf. Recall is preserved, nothing is dropped, only calibrated.
 */
type FileContext = "source" | "docs" | "test";

function classifyFile(relPath: string): FileContext {
  const p = relPath.toLowerCase();
  if (/\.(md|mdx|markdown|rst|txt|adoc)$/.test(p) || /(^|\/)docs?\//.test(p)) return "docs";
  if (
    /\.(test|spec|stories)\.[a-z0-9]+$/.test(p) ||
    /(^|\/)(tests?|__tests__|__mocks__|__fixtures__|fixtures?|examples?|e2e|mocks?)\//.test(p)
  ) {
    return "test";
  }
  return "source";
}

const SEVERITY_LADDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

/** Drop a severity by `steps` rungs (clamped), used to de-rate matches in docs/tests. */
function lowerSeverity(base: Severity, steps: number): Severity {
  const index = SEVERITY_LADDER.indexOf(base);
  return SEVERITY_LADDER[Math.min(SEVERITY_LADDER.length - 1, index + steps)] ?? "info";
}

/**
 * Effective severity + confidence for a base severity given the file context.
 * `tier` is the source-context confidence a caller earned: `confirmed` for an
 * import-resolved AST match, `high` for a distinctive-but-unresolved AST match or
 * a well-formed PEM block, `medium` for a plain regex match. In docs/tests every
 * match is de-rated to `low` and its severity dropped two rungs, regardless.
 */
function calibrate(
  base: Severity,
  context: FileContext,
  tier: Confidence = "medium",
): { severity: Severity; confidence: Confidence } {
  if (context === "source") {
    return { severity: base, confidence: tier };
  }
  return { severity: lowerSeverity(base, 2), confidence: "low" };
}

class IdAllocator {
  private counters = new Map<string, number>();

  next(prefix: string): string {
    const value = (this.counters.get(prefix) ?? 0) + 1;
    this.counters.set(prefix, value);
    return `CSW-${prefix}-${String(value).padStart(3, "0")}`;
  }
}

function lineNumber(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i += 1) {
    if (content.charCodeAt(i) === 0x0a) line += 1;
  }
  return line;
}

function* matchAll(
  content: string,
  pattern: RegExp,
): Generator<{ index: number; match: RegExpExecArray }> {
  const regex = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);
  let match: RegExpExecArray | null;
  while ((match = regex.exec(content)) !== null) {
    yield { index: match.index, match };
    if (match.index === regex.lastIndex) regex.lastIndex += 1;
  }
}

/** Scan a single file's content. Pure, drives the source scanner tests. */
export function scanContent(relPath: string, content: string, ids = new IdAllocator()): Finding[] {
  const findings: Finding[] = [];
  const context = classifyFile(relPath);
  const at = (index: number): string => `${relPath}:${lineNumber(content, index)}`;

  const push: PushFinding = (prefix, baseSeverity, category, title, index, pq, recommendation, opts = {}) => {
    const { severity, confidence } = calibrate(baseSeverity, context, opts.tier);
    findings.push({
      id: ids.next(prefix),
      severity,
      category,
      title,
      evidence: at(index),
      location: { path: relPath, line: lineNumber(content, index) },
      pq_status: pq,
      confidence,
      algorithm: opts.algorithm,
      recommendation,
      references: opts.references,
    });
  };

  // Structural first-pass for JS/TS. When it parses cleanly it owns hash/cipher/jwt
  // (already pushed), so the regexes below are skipped for that file to avoid
  // double counting; anything else falls through to the regex sweep.
  let ast: ScanJsResult = { used: "fallback", stringRanges: [] };
  if (isJsTsFile(relPath)) ast = scanJsAst(relPath, content, push);

  if (ast.used !== "ast") {
    for (const { index, match } of matchAll(content, WEAK_HASH)) {
      push(
        "SRC",
        "high",
        "source",
        `Weak hash algorithm via node:crypto (${match[1]})`,
        index,
        "vulnerable",
        "Replace MD5/SHA-1 with SHA-256 or SHA-3; both are already collision-broken classically.",
        { algorithm: /^md5$/i.test(match[1] ?? "") ? "MD5" : "SHA-1", references: [REFS.cwe327, REFS.sp800131a] },
      );
    }

    for (const { index, match } of matchAll(content, WEAK_CIPHER)) {
      push(
        "SRC",
        "high",
        "source",
        `Weak symmetric cipher via node:crypto (${match[1]})`,
        index,
        "vulnerable",
        "Replace DES/3DES/RC4/RC2 with AES-256-GCM and re-key affected data.",
        { algorithm: (match[1] ?? "").toUpperCase(), references: [REFS.cwe327] },
      );
    }

    if (JWT_USAGE.test(content)) {
      for (const { index, match } of matchAll(content, JWT_ALG)) {
        const alg = match[1] ?? "unknown";
        const { severity, pq, note } = jwtAssessment(alg);
        push("JWT", severity, "jwt", `JSON Web Token algorithm ${alg}`, index, pq, note, { algorithm: `JWT-${alg}` });
      }
    }
  }

  // PEM keys always run in both paths (a key in a comment is still a leak). When
  // the AST ran, a key sitting inside a real string/template literal is upgraded
  // from `high` to `confirmed`.
  for (const { index } of matchAll(content, PRIVATE_KEY)) {
    const inLiteral = ast.used === "ast" && ast.stringRanges.some(([s, e]) => index >= s && index < e);
    push(
      "KEY",
      "critical",
      "keys",
      "Hardcoded private key block",
      index,
      "vulnerable",
      "Remove the key from source, rotate it immediately, and load secrets from a vault/KMS.",
      { tier: inLiteral ? "confirmed" : "high" },
    );
  }

  for (const { index } of matchAll(content, PUBLIC_KEY)) {
    push(
      "KEY",
      "medium",
      "keys",
      "Embedded PEM public key (RSA/EC)",
      index,
      "vulnerable",
      "Inventory the key; RSA/EC public keys are pinned trust anchors that need a PQ migration plan.",
    );
  }

  return findings;
}

function isProbablyBinary(buffer: Buffer): boolean {
  const sample = buffer.subarray(0, 8192);
  return sample.includes(0);
}

/**
 * Read and scan one file.
 *
 * Size is checked with `stat` BEFORE the read, so an oversized file is never
 * buffered into memory (which is the resource ceiling this scanner promises),
 * and every I/O failure degrades to a recorded skip. One unreadable file in a
 * repo — a `chmod 000` fixture, an odd mode in a CI checkout — used to abort the
 * whole scan and discard every finding already collected.
 */
async function scanFile(
  full: string,
  relPath: string,
  maxFileBytes: number,
  ids: IdAllocator,
  findings: Finding[],
  budget: WalkBudget,
): Promise<void> {
  let size: number;
  try {
    size = (await stat(full)).size;
  } catch {
    recordSkipped(budget, relPath);
    return;
  }
  if (size > maxFileBytes) return;

  let buffer: Buffer;
  try {
    buffer = await readFile(full);
  } catch {
    recordSkipped(budget, relPath);
    return;
  }
  if (buffer.byteLength > maxFileBytes || isProbablyBinary(buffer)) return;
  budget.files -= 1;
  budget.bytes -= buffer.byteLength;
  findings.push(...scanContent(relPath, buffer.toString("utf8"), ids));
}

async function walk(
  rootDir: string,
  currentDir: string,
  ignoreDirs: Set<string>,
  maxFileBytes: number,
  ids: IdAllocator,
  findings: Finding[],
  budget: WalkBudget,
): Promise<void> {
  let entries;
  try {
    entries = await readdir(currentDir, { withFileTypes: true });
  } catch {
    recordSkipped(budget, relativeTo(rootDir, currentDir));
    return;
  }
  for (const entry of entries) {
    if (budget.files <= 0 || budget.bytes <= 0) {
      budget.truncated = true;
      return;
    }
    if (entry.isSymbolicLink()) continue;
    const full = join(currentDir, entry.name);
    if (entry.isDirectory()) {
      if (ignoreDirs.has(entry.name)) continue;
      await walk(rootDir, full, ignoreDirs, maxFileBytes, ids, findings, budget);
    } else if (entry.isFile()) {
      await scanFile(full, relativeTo(rootDir, full) || entry.name, maxFileBytes, ids, findings, budget);
    }
  }
}

function relativeTo(rootDir: string, full: string): string {
  return full.startsWith(rootDir) ? full.slice(rootDir.length).replace(/^[/\\]/, "") : full;
}

/** Recursively scan a local directory for quantum-vulnerable crypto. */
export async function scanSource(rootDir: string, options: SourceScanOptions = {}): Promise<Finding[]> {
  const ignoreDirs = new Set([...DEFAULT_IGNORE_DIRS, ...(options.ignoreDirs ?? [])]);
  const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const findings: Finding[] = [];
  const budget: WalkBudget = {
    files: options.maxFiles ?? DEFAULT_MAX_FILES,
    bytes: options.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES,
    truncated: false,
    skipped: { count: 0, names: [] },
  };
  await walk(rootDir, rootDir, ignoreDirs, maxFileBytes, new IdAllocator(), findings, budget);
  if (budget.skipped.count > 0) {
    const named = budget.skipped.names.join(", ");
    const more = budget.skipped.count - budget.skipped.names.length;
    findings.push({
      id: "CSW-COV-001",
      ruleId: "source/unreadable-path",
      severity: "info",
      category: "source",
      title: `${budget.skipped.count} path(s) could not be read, coverage is incomplete`,
      evidence: more > 0 ? `${named}, and ${more} more` : named,
      pq_status: "unknown",
      confidence: "confirmed",
      recommendation:
        "Grant the scanning user read access to these paths (or exclude them deliberately) so they are not a silent gap in the inventory.",
    });
  }
  if (budget.truncated) {
    findings.push({
      id: "CSW-SRC-000",
      ruleId: "source/scan-truncated",
      severity: "info",
      category: "source",
      title: "Source scan stopped at a resource limit, coverage is incomplete",
      evidence: `${rootDir} (file or byte cap reached)`,
      pq_status: "unknown",
      confidence: "confirmed",
      recommendation:
        "Some files were not analyzed. Raise maxFiles/maxTotalBytes or scan subdirectories individually for full coverage.",
    });
  }
  return findings;
}

export interface ClonedRepo {
  dir: string;
  cleanup: () => Promise<void>;
}

const SAFE_REPO_URL = /^(?:https:\/\/[\w.-]+\/[\w./-]+?(?:\.git)?|git@[\w.-]+:[\w./-]+?(?:\.git)?)$/;

/** Shallow-clone a github repo into a temp dir. The caller must invoke cleanup(). */
export async function cloneRepo(url: string): Promise<ClonedRepo> {
  if (!SAFE_REPO_URL.test(url)) {
    throw new Error(`Refusing to clone unsafe repository URL: ${url}`);
  }
  const dir = await mkdtemp(join(tmpdir(), "cryptosweep-"));
  try {
    await execFileAsync("git", ["clone", "--depth", "1", "--quiet", url, dir], { timeout: 120_000 });
  } catch (err) {
    await rm(dir, { recursive: true, force: true });
    throw err instanceof Error ? err : new Error(String(err));
  }
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true }) };
}
