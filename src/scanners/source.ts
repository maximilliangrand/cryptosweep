/**
 * Source-code crypto scanner.
 *
 * Walks a local directory and inventories the cryptography each file uses,
 * driven by the rule table in source-rules.ts:
 *   - JavaScript/TypeScript is parsed (source-ast.ts), so a match in a comment
 *     or an unrelated string never fires and callees resolve to their module;
 *     a file that does not parse falls back to the JavaScript regexes;
 *   - Python, Go and JVM sources are matched with linear regexes over the file
 *     with its comments blanked out, at `medium` confidence;
 *   - any other file gets the JavaScript regex sweep (embedded scripts, docs);
 *   - PEM private and public keys are looked for in every file.
 *
 * Every finding carries a stable `ruleId` and a repository-relative,
 * forward-slash path. Whatever the walk could not analyse (unreadable,
 * oversized, binary, over a resource ceiling) is reported as an `info` coverage
 * finding, so a clean result never hides a gap. What it skips by design
 * (walk-policy.ts: dependency, build, virtual-environment and cache
 * directories; source maps and non-code binaries) is recorded the same way,
 * without counting as a gap. Matches under documentation, test, fixture and
 * example paths carry `location.context`. Directory entries are visited in
 * sorted order, so finding order and ids do not depend on the filesystem.
 * Remote repositories are cloned by clone.ts, behind the SSRF guard.
 */
import { createPublicKey } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { constants } from "node:fs";
import type { Dirent } from "node:fs";
import { open, opendir } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import type { Category, Confidence, Finding, NonProductionContext, Severity } from "../report";
import { curveFriendlyName, keyAlgorithmLabel } from "../crypto";
import type { KeyType } from "../crypto";
import { isJsTsFile, scanJsAst } from "./source-ast";
import type { ScanJsResult } from "./source-ast";
import { REGEX_MATCHERS, REGEX_WINDOW_CHARS, assess, sourceRule, withLineRole } from "./source-rules";
import type { RegexLanguage, RegexMatcher, RuleHit, RuleId, RuleSelection } from "./source-rules";
import { DEFAULT_IGNORE_DIRS, SKIP_MARKERS, UNREPORTED_SKIPS, directoryContext } from "./walk-policy";

export interface SourceScanOptions {
  /** Directories skipped during the walk. */
  ignoreDirs?: string[];
  /** Files larger than this (bytes) are skipped, and reported as a coverage gap. */
  maxFileBytes?: number;
  /** Maximum number of files to open before stopping (bounds a hostile repo). */
  maxFiles?: number;
  /** Maximum total bytes to read before stopping, binary sniffs included. */
  maxTotalBytes?: number;
}

const DEFAULT_MAX_FILES = 25_000;
const DEFAULT_MAX_TOTAL_BYTES = 300_000_000;
const DEFAULT_MAX_FILE_BYTES = 2_000_000;
/** Entries read from one directory; a larger directory truncates the scan (reported). */
const MAX_DIR_ENTRIES = 100_000;
/** A NUL byte in this prefix marks a file as binary; only the prefix is read. */
const BINARY_SNIFF_BYTES = 8192;
/** Findings reported per file; the rest are counted in a coverage finding. */
const MAX_FINDINGS_PER_FILE = 500;
/** How many paths a coverage finding names; the rest are counted only. */
const MAX_NAMED_PATHS = 10;

/**
 * Binary files whose extension says they hold no source code or PEM text:
 * images, fonts, audio and video, documents, WebAssembly and Python bytecode.
 * Skipping one is recorded, but is not a coverage gap. Any other binary is a
 * gap, key stores (`.der`, `.p12`, `.pfx`, `.jks`) included.
 */
const NON_CODE_BINARY =
  /\.(?:png|jpe?g|gif|webp|avif|ico|icns|bmp|tiff?|psd|woff2?|ttf|otf|eot|mp3|mp4|m4a|wav|ogg|oga|flac|webm|mov|avi|pdf|wasm|pyc|pyo)$/i;

/** Source maps: generated from sources that are scanned in their own right (their `sourcesContent` would double-count them). */
const SOURCE_MAP = /\.(?:[cm]?[jt]sx?|css)\.map$/i;

/** A bounded sample of paths for a coverage finding. */
interface PathSample {
  count: number;
  names: string[];
}

function newSample(): PathSample {
  return { count: 0, names: [] };
}

function record(sample: PathSample, relPath: string): void {
  sample.count += 1;
  if (sample.names.length < MAX_NAMED_PATHS) sample.names.push(relPath);
}

function describeSample(sample: PathSample): string {
  const more = sample.count - sample.names.length;
  const named = sample.names.join(", ");
  return more > 0 ? `${named}, and ${more} more` : named;
}

// ---------------------------------------------------------------------------
// PEM key blocks
// ---------------------------------------------------------------------------

/**
 * PEM armor for private and public keys. Only the BEGIN marker is a regex; the
 * body is checked by {@link readPemBody}, one bounded forward scan. The old
 * all-in-one pattern had three overlapping newline quantifiers and backtracked
 * cubically: a 6 KB file of newlines after a BEGIN marker hung the scanner.
 *
 * A block is only flagged when it has a real base64 body before the END marker.
 * A bare header or a `...`-elided snippet (as in READMEs and docs) does not
 * count, which alone kills the most common false critical. RFC 1421 headers
 * (`Proc-Type: 4,ENCRYPTED` / `DEK-Info: …`) are skipped explicitly:
 * passphrase-protected keys are the most common committed-key form, precisely
 * because developers believe the passphrase makes committing them safe.
 */
const PEM_BEGIN =
  /-----BEGIN ((?:(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)|(?:RSA )?PUBLIC KEY)-----/g;
/** A PEM body longer than this is not a key (a 16384-bit RSA key is about 13 KB). */
const PEM_MAX_BODY_CHARS = 64 * 1024;
/** Armor headers (`Proc-Type:`, `DEK-Info:`, OpenPGP `Version:`) allowed before the body. */
const PEM_MAX_HEADER_LINES = 16;
const PEM_MAX_HEADER_CHARS = 1024;
/** Bodies shorter than this are elisions, not keys. */
const PEM_MIN_BASE64_CHARS = 40;

function isAsciiLetter(code: number): boolean {
  return (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a);
}

function isAsciiDigit(code: number): boolean {
  return code >= 0x30 && code <= 0x39;
}

function isBase64Char(code: number): boolean {
  return isAsciiLetter(code) || isAsciiDigit(code) || code === 0x2b || code === 0x2f || code === 0x3d; // + / =
}

function isBlank(code: number): boolean {
  return code === 0x20 || code === 0x09;
}

/** `Name: value`, where Name is a letter followed by word characters or dashes. */
function isArmorHeader(content: string, start: number, end: number): boolean {
  if (end - start > PEM_MAX_HEADER_CHARS || !isAsciiLetter(content.charCodeAt(start))) return false;
  for (let i = start + 1; i < end; i += 1) {
    const c = content.charCodeAt(i);
    if (c === 0x3a) return true; // ':'
    if (!isAsciiLetter(c) && !isAsciiDigit(c) && c !== 0x5f && c !== 0x2d) return false;
  }
  return false;
}

/**
 * End of the line starting at `pos` (exclusive) and the start of the next.
 * A JSON-escaped `\n` also ends a line, so a key inside a service-account JSON
 * file (`"-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END..."`) is seen.
 */
function lineBounds(content: string, pos: number, limit: number): { end: number; next: number } {
  for (let i = pos; i < limit; i += 1) {
    const c = content.charCodeAt(i);
    if (c === 0x0a) return { end: i, next: i + 1 };
    if (c === 0x0d) return { end: i, next: content.charCodeAt(i + 1) === 0x0a ? i + 2 : i + 1 };
    if (c === 0x5c) {
      const escaped = content.charCodeAt(i + 1);
      if (escaped === 0x6e) return { end: i, next: i + 2 }; // \n
      if (escaped === 0x72) {
        const crlf = content.charCodeAt(i + 2) === 0x5c && content.charCodeAt(i + 3) === 0x6e;
        return { end: i, next: crlf ? i + 4 : i + 2 }; // \r or \r\n
      }
    }
  }
  return { end: limit, next: limit };
}

/**
 * Validate the PEM body that starts at `start` (just past the BEGIN marker):
 * optional armor headers, blank lines and indentation, then only base64 up to
 * a `-----END` marker. Each character is visited at most twice and the scan is
 * capped at {@link PEM_MAX_BODY_CHARS}, so the cost is linear on any input.
 *
 * Returns the base64 lines of a well-formed body, otherwise null.
 */
function readPemBody(content: string, start: number): string[] | null {
  const limit = Math.min(content.length, start + PEM_MAX_BODY_CHARS);
  const lines: string[] = [];
  let base64Chars = 0;
  let headers = 0;
  let inHeaders = true;
  let pos = start;
  while (pos < limit) {
    const { end, next } = lineBounds(content, pos, limit);
    let s = pos;
    let e = end;
    pos = next;
    while (s < e && isBlank(content.charCodeAt(s))) s += 1;
    while (e > s && isBlank(content.charCodeAt(e - 1))) e -= 1;
    if (s === e) continue;
    if (inHeaders && isArmorHeader(content, s, e)) {
      headers += 1;
      if (headers > PEM_MAX_HEADER_LINES) return null;
      continue;
    }
    inHeaders = false;
    for (let i = s; i < e; i += 1) {
      const c = content.charCodeAt(i);
      if (isBase64Char(c)) {
        base64Chars += 1;
      } else if (c === 0x2d && content.startsWith("-----END", i)) {
        if (i > s) lines.push(content.slice(s, i));
        return base64Chars >= PEM_MIN_BASE64_CHARS ? lines : null;
      } else {
        return null;
      }
    }
    lines.push(content.slice(s, e));
  }
  return null;
}

const CLASSICAL_KEY_TYPES: ReadonlySet<string> = new Set(["rsa", "rsa-pss", "dsa", "ec", "ed25519", "ed448"]);

function isClassicalKeyType(type: string): type is Exclude<KeyType, "unknown"> {
  return CLASSICAL_KEY_TYPES.has(type);
}

const PQ_KEY_TYPE = /^(?:ml-dsa|slh-dsa|ml-kem)-/;

function parsePublicKey(pem: string): KeyObject | null {
  try {
    return createPublicKey(pem);
  } catch {
    return null;
  }
}

/**
 * Classify an embedded public key by parsing it, instead of assuming RSA/EC:
 * an ML-DSA or SLH-DSA key is post-quantum and needs no migration, while a
 * classical key is graded like any other key (a 1024-bit RSA key is weak today).
 */
function publicKeyHit(index: number, label: string, body: readonly string[]): RuleHit {
  const rule: RuleId = "keys/public-key-block";
  const key = parsePublicKey(`-----BEGIN ${label}-----\n${body.join("\n")}\n-----END ${label}-----\n`);
  const type = key?.asymmetricKeyType;
  if (!key || !type) {
    const selection: RuleSelection =
      label === "RSA PUBLIC KEY"
        ? { rule, algorithm: "RSA", detail: "RSA, did not parse" }
        : { rule, detail: "did not parse", severity: "low", pq: "unknown", note: "The key did not parse, so its algorithm is unknown." };
    return { index, tier: "medium", selection };
  }
  if (PQ_KEY_TYPE.test(type)) {
    const algorithm = type.toUpperCase();
    return {
      index,
      tier: "confirmed",
      selection: { rule, algorithm, detail: algorithm, severity: "info", pq: "safe", note: "This is a post-quantum key; it needs no migration." },
    };
  }
  if (isClassicalKeyType(type)) {
    const details = key.asymmetricKeyDetails ?? {};
    const bits = details.modulusLength;
    const curve = curveFriendlyName(details.namedCurve) ?? undefined;
    const algorithm = keyAlgorithmLabel(type, bits ?? null, curve ?? null);
    return { index, tier: "confirmed", selection: { rule, algorithm, detail: algorithm, bits, curve } };
  }
  if (type === "x25519" || type === "x448" || type === "dh") {
    const algorithm = type === "dh" ? "DH" : type.toUpperCase();
    return { index, tier: "confirmed", selection: { rule, algorithm, detail: algorithm } };
  }
  return { index, tier: "confirmed", selection: { rule, detail: type, severity: "low", pq: "unknown" } };
}

/**
 * Membership test for "offset lies inside a string literal". Ranges are sorted
 * by start; a prefix maximum of their ends makes each query a binary search,
 * so a file with many keys and many strings stays linear-logarithmic.
 */
function literalLookup(ranges: ReadonlyArray<readonly [number, number]>): (offset: number) => boolean {
  const maxEnd: number[] = [];
  for (const [, end] of ranges) maxEnd.push(Math.max(end, maxEnd[maxEnd.length - 1] ?? 0));
  return (offset) => {
    let lo = 0;
    let hi = ranges.length - 1;
    let found = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if ((ranges[mid]?.[0] ?? Infinity) <= offset) {
        found = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return found >= 0 && (maxEnd[found] ?? 0) > offset;
  };
}

/**
 * PEM key blocks run on every file and in every language: a key in a comment
 * is still a leak. When the AST ran, a private key inside a real string or
 * template literal is upgraded from `high` to `confirmed`.
 */
function keyHits(content: string, ast: ScanJsResult | null): RuleHit[] {
  const hits: RuleHit[] = [];
  const inLiteral = ast?.used === "ast" ? literalLookup(ast.stringRanges) : null;
  for (const { index, match } of matchAll(content, PEM_BEGIN)) {
    const label = match[1] ?? "";
    const body = readPemBody(content, index + match[0].length);
    if (!body) continue;
    if (label.includes("PRIVATE")) {
      hits.push({ index, tier: inLiteral?.(index) ? "confirmed" : "high", selection: { rule: "keys/private-key-block" } });
    } else {
      hits.push(publicKeyHit(index, label, body));
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------
// Regex languages
// ---------------------------------------------------------------------------

type SourceLanguage = "javascript" | RegexLanguage | "other" | "manifest";

/**
 * Dependency manifests and lockfiles belong to the dependency scanner. They
 * name libraries (`"jsonwebtoken": ...`) next to arbitrary quoted strings, so
 * the JavaScript regex sweep would read them as code; only key blocks are
 * looked for in them.
 */
const DEPENDENCY_FILES: ReadonlySet<string> = new Set([
  "package.json",
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  "Cargo.lock",
  "poetry.lock",
  "uv.lock",
  "Pipfile.lock",
  "composer.lock",
  "Gemfile.lock",
]);

function languageOf(relPath: string): SourceLanguage {
  if (DEPENDENCY_FILES.has(relPath.slice(relPath.lastIndexOf("/") + 1))) return "manifest";
  if (isJsTsFile(relPath)) return "javascript";
  const p = relPath.toLowerCase();
  if (/\.(?:py|pyw|pyi)$/.test(p)) return "python";
  if (p.endsWith(".go")) return "go";
  if (/\.(?:java|kt|kts|scala|groovy)$/.test(p)) return "java";
  return "other";
}

const REGEX_BY_LANGUAGE: ReadonlyMap<RegexLanguage, readonly RegexMatcher[]> = (() => {
  const map = new Map<RegexLanguage, RegexMatcher[]>();
  for (const matcher of REGEX_MATCHERS) {
    const list = map.get(matcher.language) ?? [];
    list.push(matcher);
    map.set(matcher.language, list);
  }
  return map;
})();

/**
 * Index just past the closing `quote` of a string starting at `from`. With
 * `escapes`, a backslash skips the next character; a single-line string also
 * ends at a newline (unterminated), and the end of the file ends any string.
 */
function skipQuoted(content: string, from: number, quote: string, multiline: boolean, escapes: boolean): number {
  let i = from;
  while (i < content.length) {
    const c = content[i];
    if (escapes && c === "\\") {
      i += 2;
      continue;
    }
    if (content.startsWith(quote, i)) return i + quote.length;
    if (!multiline && c === "\n") return i;
    i += 1;
  }
  return content.length;
}

/**
 * Blank out comments, keeping every offset and newline so line numbers and
 * match positions are unchanged. Strings are skipped, not blanked: algorithm
 * names live in them. One forward pass, linear in the file size.
 */
function stripComments(content: string, language: RegexLanguage): string {
  const ranges: Array<[number, number]> = [];
  const hashComments = language === "python";
  let i = 0;
  while (i < content.length) {
    const c = content[i];
    if (hashComments && c === "#") {
      const end = content.indexOf("\n", i);
      ranges.push([i, end < 0 ? content.length : end]);
      i = end < 0 ? content.length : end;
    } else if (!hashComments && c === "/" && content[i + 1] === "/") {
      const end = content.indexOf("\n", i);
      ranges.push([i, end < 0 ? content.length : end]);
      i = end < 0 ? content.length : end;
    } else if (!hashComments && c === "/" && content[i + 1] === "*") {
      const end = content.indexOf("*/", i + 2);
      const stop = end < 0 ? content.length : end + 2;
      ranges.push([i, stop]);
      i = stop;
    } else if ((c === '"' || c === "'") && content.startsWith(c.repeat(3), i) && language !== "go") {
      i = skipQuoted(content, i + 3, c.repeat(3), true, true);
    } else if (c === '"' || c === "'") {
      i = skipQuoted(content, i + 1, c, false, true);
    } else if (c === "`" && language === "go") {
      i = skipQuoted(content, i + 1, "`", true, false);
    } else {
      i += 1;
    }
  }
  if (ranges.length === 0) return content;
  let out = "";
  let last = 0;
  for (const [start, end] of ranges) {
    out += content.slice(last, start) + content.slice(start, end).replace(/[^\n]/g, " ");
    last = end;
  }
  return out + content.slice(last);
}

function* matchAll(content: string, pattern: RegExp): Generator<{ index: number; match: RegExpExecArray }> {
  const regex = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);
  let match: RegExpExecArray | null;
  while ((match = regex.exec(content)) !== null) {
    yield { index: match.index, match };
    if (match.index === regex.lastIndex) regex.lastIndex += 1;
  }
}

/** Characters either side of a match read as its line, for weak-hash role inference. */
const LINE_CONTEXT_CHARS = 160;

/** The match's own line, at most {@link LINE_CONTEXT_CHARS} either side of it, without the match. */
function lineAround(text: string, start: number, end: number): string {
  const before = text.slice(Math.max(0, start - LINE_CONTEXT_CHARS), start);
  const after = text.slice(end, end + LINE_CONTEXT_CHARS);
  const newlineBefore = before.lastIndexOf("\n");
  const newlineAfter = after.indexOf("\n");
  return `${newlineBefore < 0 ? before : before.slice(newlineBefore + 1)} ${newlineAfter < 0 ? after : after.slice(0, newlineAfter)}`;
}

/** Run one language's regex matchers; every match is `medium` evidence. */
function regexHits(text: string, language: RegexLanguage): RuleHit[] {
  const hits: RuleHit[] = [];
  const gates = new Map<RegExp, boolean>();
  for (const matcher of REGEX_BY_LANGUAGE.get(language) ?? []) {
    if (matcher.gate) {
      let open = gates.get(matcher.gate);
      if (open === undefined) {
        open = matcher.gate.test(text);
        gates.set(matcher.gate, open);
      }
      if (!open) continue;
    }
    for (const { index, match } of matchAll(text, matcher.pattern)) {
      const end = index + match[0].length;
      const after = text.slice(end, end + REGEX_WINDOW_CHARS);
      for (const selection of matcher.classify(match, after)) {
        hits.push({ index, tier: "medium", selection: withLineRole(selection, () => lineAround(text, index, end)) });
      }
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/**
 * Where a match was found. A weak primitive in a real source file is a live code
 * path; the same string in documentation or a test fixture is usually an
 * example, so we lower its severity and mark the finding low-confidence rather
 * than crying wolf. Recall is preserved, nothing is dropped, only calibrated.
 */
type FileContext = "source" | NonProductionContext;

function classifyFile(relPath: string): FileContext {
  const p = relPath.toLowerCase();
  const directory = directoryContext(relPath);
  if (/\.(md|mdx|markdown|rst|txt|adoc)$/.test(p) || directory === "docs") return "docs";
  if (/\.(test|spec|stories)\.[a-z0-9]+$/.test(p)) return "test";
  return directory ?? "source";
}

const SEVERITY_LADDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

/** Drop a severity by `steps` rungs (clamped), used to de-rate matches in docs/tests. */
function lowerSeverity(base: Severity, steps: number): Severity {
  const index = SEVERITY_LADDER.indexOf(base);
  return SEVERITY_LADDER[Math.min(SEVERITY_LADDER.length - 1, index + steps)] ?? "info";
}

/**
 * Effective severity + confidence for a match given the file context. `tier`
 * is the confidence the evidence earned (see source-rules.ts). In docs/tests
 * every match is de-rated to `low` and its severity dropped two rungs.
 */
function calibrate(base: Severity, context: FileContext, tier: Confidence): { severity: Severity; confidence: Confidence } {
  if (context === "source") return { severity: base, confidence: tier };
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

const ID_PREFIX: Record<Category, string> = { source: "SRC", jwt: "JWT", keys: "KEY", deps: "DEP", tls: "TLS" };

/**
 * 1-based line lookup. Newline offsets are computed once per file and each
 * query is a binary search; rescanning from offset 0 for every finding was
 * quadratic and let one hostile file pin the CPU for minutes.
 */
class LineIndex {
  private readonly starts: number[] = [0];

  constructor(content: string) {
    for (let i = content.indexOf("\n"); i !== -1; i = content.indexOf("\n", i + 1)) this.starts.push(i + 1);
  }

  lineOf(offset: number): number {
    let lo = 0;
    let hi = this.starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if ((this.starts[mid] ?? 0) <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  }
}

function byPosition(a: RuleHit, z: RuleHit): number {
  if (a.index !== z.index) return a.index - z.index;
  return a.selection.rule < z.selection.rule ? -1 : a.selection.rule > z.selection.rule ? 1 : 0;
}

function toFinding(hit: RuleHit, relPath: string, context: FileContext, lines: LineIndex, ids: IdAllocator): Finding {
  const a = assess(hit);
  const { severity, confidence } = calibrate(a.severity, context, a.confidence);
  const line = lines.lineOf(hit.index);
  return {
    id: ids.next(ID_PREFIX[a.rule.category]),
    ruleId: a.rule.id,
    severity,
    category: a.rule.category,
    title: a.title,
    evidence: `${relPath}:${line}`,
    location: { path: relPath, ...(context === "source" ? {} : { context }), line },
    pq_status: a.pq,
    confidence,
    ...(a.algorithm ? { algorithm: a.algorithm } : {}),
    ...(a.classicalBreak ? { classicalBreak: a.classicalBreak } : {}),
    ...(a.rule.findingUsage.length > 0 ? { usage: [...a.rule.findingUsage] } : {}),
    recommendation: a.recommendation,
    ...(a.references.length > 0 ? { references: a.references } : {}),
  };
}

interface ContentAnalysis {
  findings: Finding[];
  /** Matches beyond the per-file cap, not reported. */
  dropped: number;
  /** A JS/TS file that went through the regex fallback instead of the AST. */
  fallback: boolean;
}

function analyzeContent(relPath: string, content: string, ids: IdAllocator): ContentAnalysis {
  const language = languageOf(relPath);
  const hits: RuleHit[] = [];
  let ast: ScanJsResult | null = null;
  let fallback = false;
  if (language === "javascript") {
    ast = scanJsAst(relPath, content);
    fallback = ast.used !== "ast";
    hits.push(...(fallback ? regexHits(content, "javascript") : ast.hits));
  } else if (language === "other") {
    hits.push(...regexHits(content, "javascript"));
  } else if (language !== "manifest") {
    hits.push(...regexHits(stripComments(content, language), language));
  }
  hits.push(...keyHits(content, ast));

  const seen = new Set<string>();
  const unique = hits.sort(byPosition).filter((hit) => {
    const key = `${hit.index}|${hit.selection.rule}|${hit.selection.algorithm ?? ""}|${hit.selection.detail ?? ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  const kept = unique.slice(0, MAX_FINDINGS_PER_FILE);
  const context = classifyFile(relPath);
  const lines = new LineIndex(kept.length > 0 ? content : "");
  return {
    findings: kept.map((hit) => toFinding(hit, relPath, context, lines, ids)),
    dropped: unique.length - kept.length,
    fallback,
  };
}

function coverageFinding(id: string, rule: RuleId, title: string, evidence: string): Finding {
  return {
    id,
    ruleId: rule,
    severity: "info",
    category: "source",
    title,
    evidence,
    pq_status: "unknown",
    confidence: "confirmed",
    recommendation: sourceRule(rule).recommendation,
  };
}

/** Scan a single file's content. Pure, drives the source scanner tests. */
export function scanContent(relPath: string, content: string, ids = new IdAllocator()): Finding[] {
  const { findings, dropped } = analyzeContent(relPath, content, ids);
  if (dropped > 0) {
    findings.push(
      coverageFinding(
        ids.next("COV"),
        "source/findings-capped",
        `${dropped} further match(es) in ${relPath} were not reported (per-file cap of ${MAX_FINDINGS_PER_FILE})`,
        relPath,
      ),
    );
  }
  return findings;
}

// ---------------------------------------------------------------------------
// The walk
// ---------------------------------------------------------------------------

interface WalkState {
  readonly rootDir: string;
  readonly ignoreDirs: ReadonlySet<string>;
  readonly maxFileBytes: number;
  readonly ids: IdAllocator;
  readonly findings: Finding[];
  /** Remaining budgets. */
  files: number;
  bytes: number;
  /** Totals, for the truncation evidence. */
  filesOpened: number;
  bytesRead: number;
  truncated: boolean;
  readonly unreadable: PathSample;
  readonly oversized: PathSample;
  readonly binary: PathSample;
  readonly capped: PathSample;
  readonly fallback: PathSample;
  /** Directories skipped by policy (dependencies, build output, virtual environments, caches). */
  readonly skippedDirs: PathSample;
  /** Source maps and non-code binaries, skipped without leaving a coverage gap. */
  readonly nonCode: PathSample;
}

/** Repository-relative, forward-slash path (SARIF and every finding use the same base). */
function toRelative(rootDir: string, full: string): string {
  return relative(rootDir, full).split(sep).join("/");
}

function byName(a: Dirent, z: Dirent): number {
  return a.name < z.name ? -1 : a.name > z.name ? 1 : 0;
}

async function listDirectory(dir: string): Promise<{ entries: Dirent[]; truncated: boolean }> {
  const entries: Dirent[] = [];
  let truncated = false;
  for await (const entry of await opendir(dir)) {
    if (entries.length >= MAX_DIR_ENTRIES) {
      truncated = true;
      break;
    }
    entries.push(entry);
  }
  return { entries: entries.sort(byName), truncated };
}

/** Read `[from, to)` of the file into `buffer` at the same offsets; returns the end reached. */
async function readInto(handle: FileHandle, buffer: Buffer, from: number, to: number): Promise<number> {
  let offset = from;
  while (offset < to) {
    const { bytesRead } = await handle.read(buffer, offset, to - offset, offset);
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  return offset;
}

/**
 * Open without following a symlink swapped in after the directory listing, and
 * without blocking on a FIFO. Both flags are POSIX-only and zero elsewhere.
 */
const OPEN_FLAGS = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);

/**
 * Read and scan one file. Size is checked on the open handle BEFORE any read,
 * so an oversized file is never buffered; binary detection reads only a small
 * prefix; and every byte read, binary sniffs included, is charged to the
 * budget. Every I/O failure degrades to a recorded skip: one unreadable file
 * (a `chmod 000` fixture, an odd mode in a CI checkout) used to abort the scan.
 */
async function scanFile(full: string, relPath: string, state: WalkState): Promise<void> {
  let handle: FileHandle;
  try {
    handle = await open(full, OPEN_FLAGS);
  } catch {
    record(state.unreadable, relPath);
    return;
  }
  try {
    const info = await handle.stat();
    if (!info.isFile()) {
      record(state.unreadable, relPath);
      return;
    }
    state.files -= 1;
    state.filesOpened += 1;
    if (info.size > state.maxFileBytes) {
      record(state.oversized, relPath);
      if (isJsTsFile(relPath)) record(state.fallback, relPath);
      return;
    }
    const sniff = Math.min(info.size, BINARY_SNIFF_BYTES);
    if (sniff > state.bytes) {
      state.truncated = true;
      return;
    }
    const buffer = Buffer.alloc(info.size);
    const sniffed = await readInto(handle, buffer, 0, sniff);
    state.bytes -= sniffed;
    state.bytesRead += sniffed;
    if (buffer.subarray(0, sniffed).includes(0)) {
      record(NON_CODE_BINARY.test(relPath) ? state.nonCode : state.binary, relPath);
      return;
    }
    if (info.size - sniffed > state.bytes) {
      state.truncated = true;
      return;
    }
    const end = await readInto(handle, buffer, sniffed, info.size);
    state.bytes -= end - sniffed;
    state.bytesRead += end - sniffed;
    const analysis = analyzeContent(relPath, buffer.subarray(0, end).toString("utf8"), state.ids);
    state.findings.push(...analysis.findings);
    if (analysis.dropped > 0) record(state.capped, relPath);
    if (analysis.fallback) record(state.fallback, relPath);
  } catch {
    record(state.unreadable, relPath);
  } finally {
    await handle.close().catch(() => undefined);
  }
}

/** True when a listed directory (below the root) carries a marker that makes it not the project's code. */
function hasSkipMarker(entries: readonly Dirent[]): boolean {
  return entries.some((entry) => entry.isFile() && SKIP_MARKERS.has(entry.name));
}

async function walk(dir: string, state: WalkState): Promise<void> {
  let listing: { entries: Dirent[]; truncated: boolean };
  try {
    listing = await listDirectory(dir);
  } catch {
    record(state.unreadable, toRelative(state.rootDir, dir) || ".");
    return;
  }
  if (dir !== state.rootDir && hasSkipMarker(listing.entries)) {
    record(state.skippedDirs, toRelative(state.rootDir, dir));
    return;
  }
  if (listing.truncated) state.truncated = true;
  for (const entry of listing.entries) {
    if (state.truncated || state.files <= 0 || state.bytes <= 0) {
      state.truncated = true;
      return;
    }
    if (entry.isSymbolicLink()) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!state.ignoreDirs.has(entry.name)) await walk(full, state);
      else if (!UNREPORTED_SKIPS.has(entry.name)) record(state.skippedDirs, toRelative(state.rootDir, full));
    } else if (entry.isFile()) {
      const relPath = toRelative(state.rootDir, full);
      if (SOURCE_MAP.test(entry.name)) record(state.nonCode, relPath);
      else await scanFile(full, relPath, state);
    }
  }
}

function coverageFindings(state: WalkState, maxFiles: number, maxTotalBytes: number): Finding[] {
  const out: Finding[] = [];
  const add = (sample: PathSample, rule: RuleId, title: string): void => {
    if (sample.count > 0) out.push(coverageFinding(state.ids.next("COV"), rule, title, describeSample(sample)));
  };
  const n = (sample: PathSample): number => sample.count;
  const megabytes = Math.round((state.maxFileBytes / 1_000_000) * 10) / 10;
  add(state.unreadable, "source/unreadable-path", `${n(state.unreadable)} path(s) could not be read, coverage is incomplete`);
  add(
    state.oversized,
    "source/file-too-large",
    `${n(state.oversized)} file(s) above the ${megabytes} MB per-file limit were not analysed, coverage is incomplete`,
  );
  add(state.binary, "source/binary-skipped", `${n(state.binary)} binary-looking file(s) were not analysed`);
  add(
    state.skippedDirs,
    "source/directories-skipped",
    `${n(state.skippedDirs)} dependency, build, virtual-environment or cache director(ies) were skipped by default`,
  );
  add(
    state.nonCode,
    "source/non-code-skipped",
    `${n(state.nonCode)} source map(s) and non-code binary file(s) (images, fonts, media, WebAssembly, bytecode) were not analysed`,
  );
  add(
    state.capped,
    "source/findings-capped",
    `${n(state.capped)} file(s) had more than ${MAX_FINDINGS_PER_FILE} matches; only the first ${MAX_FINDINGS_PER_FILE} per file are reported`,
  );
  add(
    state.fallback,
    "source/ast-fallback",
    `${n(state.fallback)} JavaScript/TypeScript file(s) were not analysed by the AST (parse failure or size limit)`,
  );
  if (state.truncated) {
    out.push(
      coverageFinding(
        "CSW-SRC-000",
        "source/scan-truncated",
        "Source scan stopped at a resource limit, coverage is incomplete",
        `stopped after ${state.filesOpened} file(s) and ${state.bytesRead} byte(s) (limits: ${maxFiles} files, ${maxTotalBytes} bytes, ${MAX_DIR_ENTRIES} entries per directory)`,
      ),
    );
  }
  return out;
}

/** Recursively scan a local directory for quantum-vulnerable crypto. */
export async function scanSource(rootDir: string, options: SourceScanOptions = {}): Promise<Finding[]> {
  const maxFiles = options.maxFiles ?? DEFAULT_MAX_FILES;
  const maxTotalBytes = options.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES;
  const state: WalkState = {
    rootDir,
    ignoreDirs: new Set([...DEFAULT_IGNORE_DIRS, ...(options.ignoreDirs ?? [])]),
    maxFileBytes: options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES,
    ids: new IdAllocator(),
    findings: [],
    files: maxFiles,
    bytes: maxTotalBytes,
    filesOpened: 0,
    bytesRead: 0,
    truncated: false,
    unreadable: newSample(),
    oversized: newSample(),
    binary: newSample(),
    capped: newSample(),
    fallback: newSample(),
    skippedDirs: newSample(),
    nonCode: newSample(),
  };
  await walk(rootDir, state);
  return [...state.findings, ...coverageFindings(state, maxFiles, maxTotalBytes)];
}
