/**
 * Source-code crypto scanner.
 *
 * A fast first-pass regex sweep (no TS AST) over a local directory, flagging
 * weak `node:crypto` usage, JSON Web Token algorithms, hardcoded private keys
 * and PEM-encoded public keys. The github-clone helper lets the CLI scan a
 * remote repo by URL.
 */
import { execFile } from "node:child_process";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import type { Category, Finding, PqStatus, Severity } from "../report";

const execFileAsync = promisify(execFile);

export interface SourceScanOptions {
  /** Directories skipped during the walk. */
  ignoreDirs?: string[];
  /** Files larger than this (bytes) are skipped. */
  maxFileBytes?: number;
}

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
const PRIVATE_KEY = /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----/g;
const PUBLIC_KEY = /-----BEGIN (?:RSA )?PUBLIC KEY-----/g;

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

function jwtAssessment(alg: string): { severity: Severity; pq: PqStatus; note: string } {
  if (alg === "none") {
    return { severity: "critical", pq: "vulnerable", note: 'JWT "alg: none" disables signature verification — remove it.' };
  }
  if (alg.startsWith("HS")) {
    return {
      severity: "low",
      pq: "transitional",
      note: "HMAC JWT is symmetric and quantum-resistant if the key is ≥256-bit; rotate and protect the secret.",
    };
  }
  return {
    severity: "high",
    pq: "vulnerable",
    note: `${alg} relies on RSA/ECDSA signatures broken by Shor's algorithm; plan a PQ-signature migration.`,
  };
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

/** Scan a single file's content. Pure — drives the source scanner tests. */
export function scanContent(relPath: string, content: string, ids = new IdAllocator()): Finding[] {
  const findings: Finding[] = [];
  const at = (index: number): string => `${relPath}:${lineNumber(content, index)}`;

  const push = (
    prefix: string,
    severity: Severity,
    category: Category,
    title: string,
    index: number,
    pq: PqStatus,
    recommendation: string,
  ): void => {
    findings.push({ id: ids.next(prefix), severity, category, title, evidence: at(index), pq_status: pq, recommendation });
  };

  for (const { index, match } of matchAll(content, WEAK_HASH)) {
    push(
      "SRC",
      "high",
      "source",
      `Weak hash algorithm via node:crypto (${match[1]})`,
      index,
      "vulnerable",
      "Replace MD5/SHA-1 with SHA-256 or SHA-3; both are already collision-broken classically.",
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
    );
  }

  if (JWT_USAGE.test(content)) {
    for (const { index, match } of matchAll(content, JWT_ALG)) {
      const alg = match[1] ?? "unknown";
      const { severity, pq, note } = jwtAssessment(alg);
      push("JWT", severity, "jwt", `JSON Web Token algorithm ${alg}`, index, pq, note);
    }
  }

  for (const { index } of matchAll(content, PRIVATE_KEY)) {
    push(
      "KEY",
      "critical",
      "keys",
      "Hardcoded private key block",
      index,
      "vulnerable",
      "Remove the key from source, rotate it immediately, and load secrets from a vault/KMS.",
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

async function walk(
  rootDir: string,
  ignoreDirs: Set<string>,
  maxFileBytes: number,
  ids: IdAllocator,
  findings: Finding[],
): Promise<void> {
  const entries = await readdir(rootDir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const full = join(rootDir, entry.name);
    if (entry.isDirectory()) {
      if (ignoreDirs.has(entry.name)) continue;
      await walk(full, ignoreDirs, maxFileBytes, ids, findings);
    } else if (entry.isFile()) {
      const buffer = await readFile(full);
      if (buffer.byteLength > maxFileBytes || isProbablyBinary(buffer)) continue;
      const relPath = full.startsWith(rootDir) ? full.slice(rootDir.length).replace(/^[/\\]/, "") : full;
      findings.push(...scanContent(relPath || entry.name, buffer.toString("utf8"), ids));
    }
  }
}

/** Recursively scan a local directory for quantum-vulnerable crypto. */
export async function scanSource(rootDir: string, options: SourceScanOptions = {}): Promise<Finding[]> {
  const ignoreDirs = new Set([...DEFAULT_IGNORE_DIRS, ...(options.ignoreDirs ?? [])]);
  const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const findings: Finding[] = [];
  await walk(rootDir, ignoreDirs, maxFileBytes, new IdAllocator(), findings);
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
