/**
 * Report model shared by every scanner, plus JSON + Markdown serialization.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Category = "tls" | "source" | "deps" | "jwt" | "keys";
export type PqStatus = "vulnerable" | "transitional" | "safe" | "unknown";

/**
 * How sure the scanner is that a finding is real and correctly classified.
 *
 * - `confirmed`, derived from parsed, structured evidence (an ASN.1 field, a
 *   `KeyObject`, a resolved dependency version). No guessing.
 * - `high`, a strong structural signal with a small, well-understood residual
 *   ambiguity.
 * - `medium`, a heuristic (regex) match on code with real false-positive risk.
 * - `low`, a match in a context (docs, tests, examples) where it may not be a
 *   live code path at all.
 */
export type Confidence = "confirmed" | "high" | "medium" | "low";

/** A citation backing a finding, a standard, advisory, or spec. */
export interface Reference {
  label: string;
  url?: string;
}

/** Where a finding was observed, in structured form (for SARIF / drill-down). */
export interface Location {
  /** Repo-relative file path, when the finding comes from source/deps. */
  path?: string;
  /** 1-indexed line, when known. */
  line?: number;
  /** Host, when the finding comes from a network probe. */
  host?: string;
  /** Port, when the finding comes from a network probe. */
  port?: number;
}

/**
 * What a primitive is doing where it was found. This is what the risk engine
 * reads to pick a threat model, so it never has to guess from a title:
 *
 * - `key-establishment` and `encryption` protect confidentiality: traffic or
 *   data recorded today is a harvest-now-decrypt-later target.
 * - `signature` and `authentication` protect integrity and identity: forgeable
 *   once a CRQC exists, with no retroactive harvest.
 * - `secret-material` is key material itself: a committed private key is
 *   compromised today, whatever its algorithm.
 * - `hashing` and `protocol` carry no Shor exposure of their own.
 */
export type CryptoUsage =
  | "key-establishment"
  | "encryption"
  | "signature"
  | "authentication"
  | "hashing"
  | "secret-material"
  | "protocol";

/** Parsed X.509 details of one certificate a finding concerns (drives CBOM certificate assets). */
export interface CertificateDetails {
  subject: string;
  issuer: string;
  /** Validity bounds, ISO 8601. */
  notValidBefore: string;
  notValidAfter: string;
  /** Signature-algorithm name read from the certificate's ASN.1, e.g. `sha256WithRSAEncryption`. */
  signatureAlgorithm: string;
  /** The signature-algorithm OID read from the certificate's ASN.1. */
  signatureOid?: string;
  /** Canonical public-key label, e.g. `RSA-2048`, `ECDSA-P-256`. */
  publicKey: string;
  /** Public-key size in bits, when known. */
  publicKeyBits?: number;
}

/** Negotiated protocol parameters, for a finding about a live session. */
export interface ProtocolDetails {
  /** Protocol family, e.g. `tls`, `ssh`. */
  type: string;
  /** Version without the family prefix, e.g. `1.3`. */
  version?: string;
  /** Negotiated cipher suite, e.g. `TLS_AES_256_GCM_SHA384`. */
  cipherSuite?: string;
  /** Negotiated key-exchange group, e.g. `X25519MLKEM768`. */
  group?: string;
}

/** The package a dependency finding is about. */
export interface PackageCoordinates {
  /** Ecosystem, e.g. `npm`, `python`, `cargo`. */
  ecosystem: string;
  name: string;
  /** The version or range declared in the manifest, verbatim. */
  version?: string;
}

export interface Finding {
  /** Human-facing, per-report sequential id, e.g. `CSW-TLS-001`. */
  id: string;
  /**
   * Stable rule identity shared by every finding of the same kind, e.g.
   * `tls/leaf-public-key`. Drives SARIF `ruleId`, CBOM grouping and the risk
   * engine's rule table. Optional at construction; {@link buildReport} derives
   * one from the category and algorithm (or title) when absent.
   */
  ruleId?: string;
  severity: Severity;
  category: Category;
  title: string;
  evidence: string;
  /** Structured provenance for the finding, when available. */
  location?: Location;
  pq_status: PqStatus;
  /** Scanner confidence; defaults to `medium` if a scanner does not set it. */
  confidence?: Confidence;
  /**
   * The canonical cryptographic primitive this finding concerns, normalized for
   * inventory grouping, e.g. `RSA-2048`, `ECDSA-P-256`, `Ed25519`, `SHA-1`.
   */
  algorithm?: string;
  /**
   * Why the primitive is broken classically today, independent of any quantum
   * computer, when the scanner established it from parsed parameters: a
   * modulus or finite-field group under 2048 bits, a curve under 224 bits, a
   * signature computed over MD5 or SHA-1. The risk engine reads this, not the
   * algorithm label, to put the finding on the act-now board.
   */
  classicalBreak?: string;
  recommendation: string;
  /** Standards / advisories backing the classification. */
  references?: Reference[];
  /** What the primitive is used for here, when the scanner can tell. */
  usage?: CryptoUsage[];
  /** OID of `algorithm`, read from the parsed structure (e.g. a certificate), when available. */
  oid?: string;
  /** Parsed certificate(s) this finding concerns. */
  certificates?: CertificateDetails[];
  /** Negotiated protocol parameters, for findings about a live session. */
  protocol?: ProtocolDetails;
  /** The dependency this finding is about. */
  dependency?: PackageCoordinates;
}

export interface ReportSummary {
  findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

/** What one check examined, so an empty result is never read as a clean bill of health. */
export interface CoverageEntry {
  /** The scanner or check, e.g. `source`, `deps`, `tls`. */
  check: string;
  /** What it examined, in words, e.g. `412 files`, `3 manifests`. */
  scope: string;
  /** False when the check stopped early or skipped part of its scope. */
  complete: boolean;
  /** Why coverage is partial, when it is. */
  note?: string;
}

export interface Report {
  target: string;
  scanned_at: string;
  summary: ReportSummary;
  findings: Finding[];
  /** What each check covered, when the caller recorded it. */
  coverage?: CoverageEntry[];
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function summarize(findings: Finding[]): ReportSummary {
  const summary: ReportSummary = {
    findings: findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const finding of findings) summary[finding.severity] += 1;
  return summary;
}

/**
 * Make an untrusted string safe to print: C0/C1 control characters (except
 * tab), line and paragraph separators, and bidirectional overrides become
 * visible `\xHH` / `\uHHHH` escapes. File names, certificate subjects and
 * manifest versions all come from the scanned target, and a raw ESC or BEL
 * byte in one of them is a terminal escape sequence by the time it reaches a
 * console, a CI log or an MCP client. Escaping (rather than dropping) keeps the
 * evidence recognisable, and the result is idempotent.
 */
export function sanitizeText(value: string): string {
  let out = "";
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (!isUnsafeCodePoint(code)) {
      out += char;
    } else if (code <= 0xff) {
      out += `\\x${code.toString(16).padStart(2, "0")}`;
    } else {
      out += `\\u${code.toString(16).padStart(4, "0")}`;
    }
  }
  return out;
}

function isUnsafeCodePoint(code: number): boolean {
  if (code === 0x09) return false; // tab is harmless everywhere we print
  if (code < 0x20 || (code >= 0x7f && code <= 0x9f)) return true; // C0, DEL, C1
  if (code === 0x2028 || code === 0x2029) return true; // line / paragraph separator
  return (code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069); // bidi overrides
}

/**
 * Fill in ontology defaults so every downstream consumer (CBOM, SARIF, the
 * viewer) can rely on `ruleId` and `confidence` being present, and sanitize the
 * display strings (see {@link sanitizeText}) once, at the report boundary. A
 * scanner may set the defaults explicitly; this only supplies them when it did not.
 */
export function normalizeFinding(finding: Finding): Required<Pick<Finding, "ruleId" | "confidence">> & Finding {
  return {
    ...finding,
    title: sanitizeText(finding.title),
    evidence: sanitizeText(finding.evidence),
    recommendation: sanitizeText(finding.recommendation),
    ruleId: finding.ruleId ?? deriveRuleId(finding),
    confidence: finding.confidence ?? "medium",
  };
}

/**
 * Derive a rule id for a finding whose scanner did not provide one.
 *
 * A rule is one *kind* of finding, so the id is built from what the finding is
 * about, its algorithm (or, lacking one, its title), never from the sequential
 * report id: `CSW-SRC-001` and `CSW-SRC-002` may be an MD5 hash and an RC4
 * cipher, and folding both into one `source/csw-src` rule gave SARIF consumers
 * one alert type with the wrong description and severity for half its results.
 */
function deriveRuleId(finding: Finding): string {
  return ruleIdFromLabel(finding.category, finding.algorithm ?? finding.title);
}

/** The rule id derived from a category and an algorithm label (or title): `source` + `SHA-1` -> `source/sha-1`. */
export function ruleIdFromLabel(category: string, label: string): string {
  const subject = slug(label);
  const base = subject.startsWith(`${category}-`) ? subject.slice(category.length + 1) : subject;
  return `${category}/${base || "finding"}`;
}

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

/**
 * Build a Report from raw findings, sorting by severity and stamping the scan
 * time. `coverage` records what each check examined, when the caller knows.
 */
export function buildReport(
  target: string,
  findings: Finding[],
  scannedAt: Date = new Date(),
  coverage?: CoverageEntry[],
): Report {
  const normalized = findings.map(normalizeFinding);
  const sorted = normalized.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  return {
    target: sanitizeText(target),
    scanned_at: scannedAt.toISOString(),
    summary: summarize(sorted),
    findings: sorted,
    ...(coverage ? { coverage } : {}),
  };
}

/** Serialize a report as pretty-printed JSON. */
export function toJson(report: Report): string {
  return JSON.stringify(report, null, 2);
}

/** Severities in ascending order of importance, for threshold comparisons. */
const SEVERITY_RANK: readonly Severity[] = ["info", "low", "medium", "high", "critical"];

/** True if any finding is at or above `threshold`, the CI fail-gate predicate. */
export function failsThreshold(report: Report, threshold: Severity): boolean {
  const cut = SEVERITY_RANK.indexOf(threshold);
  return report.findings.some((f) => SEVERITY_RANK.indexOf(f.severity) >= cut);
}

const SEVERITY_BADGE: Record<Severity, string> = {
  critical: "🟥 critical",
  high: "🟧 high",
  medium: "🟨 medium",
  low: "🟦 low",
  info: "⬜ info",
};

/** The empty-result line, scoped to the checks that ran rather than a blanket "all clear". */
export const NO_FINDINGS_MESSAGE = "No findings from the checks that ran.";

/**
 * What an empty result does and does not mean, for renderers. With recorded
 * coverage it names what was examined; without it, it says plainly that the
 * scope is unknown, because "no findings" from a scanner that cannot see a
 * construct is not evidence the construct is absent.
 */
export function emptyResultNote(report: Pick<Report, "coverage">): string {
  if (report.coverage && report.coverage.length > 0) {
    const partial = report.coverage.some((entry) => !entry.complete);
    return partial
      ? "Coverage was partial (below), so parts of the target were not examined."
      : "Only the constructs these checks detect were examined; see the README for each scanner's rule set.";
  }
  return (
    "This report does not record which checks ran or what they covered, so it is not evidence that the " +
    "target has no quantum-vulnerable cryptography; see the README for each scanner's rule set."
  );
}

/** One human-readable line per coverage entry. */
export function coverageLines(coverage: readonly CoverageEntry[]): string[] {
  return coverage.map((entry) => {
    const status = entry.complete ? "complete" : `partial${entry.note ? `: ${entry.note}` : ""}`;
    return `${entry.check}: ${entry.scope} (${status})`;
  });
}

/** Render a report as a human-readable Markdown summary. Every interpolated field is escaped. */
export function toMarkdown(report: Report): string {
  const { summary } = report;
  const lines: string[] = [
    `# cryptosweep report`,
    ``,
    `- **Target:** ${escapeMarkdown(report.target)}`,
    `- **Scanned at:** ${escapeMarkdown(report.scanned_at)}`,
    `- **Findings:** ${count(summary.findings)} ` +
      `(critical: ${count(summary.critical)}, high: ${count(summary.high)}, medium: ${count(summary.medium)}, ` +
      `low: ${count(summary.low)}, info: ${count(summary.info)})`,
    ``,
  ];

  if (report.findings.length === 0) {
    lines.push(NO_FINDINGS_MESSAGE, ``, escapeMarkdown(emptyResultNote(report)));
    lines.push(...coverageSection(report));
    return lines.join("\n");
  }

  lines.push(`| Severity | Category | PQ status | Confidence | Finding | Evidence |`);
  lines.push(`| --- | --- | --- | --- | --- | --- |`);
  for (const finding of report.findings) {
    lines.push(
      `| ${SEVERITY_BADGE[finding.severity]} | ${escapeMarkdown(finding.category)} | ${escapeMarkdown(finding.pq_status)} | ` +
        `${escapeMarkdown(finding.confidence ?? "medium")} | ${escapeMarkdown(finding.title)} | ` +
        `${escapeMarkdown(finding.evidence)} |`,
    );
  }

  lines.push(``, `## Recommendations`, ``);
  for (const finding of report.findings) {
    lines.push(`- **${escapeMarkdown(finding.id)}**, ${escapeMarkdown(finding.recommendation)}`);
  }
  lines.push(...coverageSection(report));

  return lines.join("\n");
}

function coverageSection(report: Report): string[] {
  if (!report.coverage || report.coverage.length === 0) return [];
  return [``, `## Coverage`, ``, ...coverageLines(report.coverage).map((line) => `- ${escapeMarkdown(line)}`)];
}

/** A summary count, coerced so a tampered report cannot smuggle markup through it. */
function count(value: unknown): string {
  const n = Number(value);
  return Number.isFinite(n) ? String(n) : "?";
}

/**
 * Escape an untrusted string for a Markdown table cell or list item: control
 * characters are made visible, and the punctuation that would open a link,
 * image, autolink, raw HTML, emphasis, code span or a new table cell is
 * backslash-escaped, so a file named `[x](https://evil)` renders as text.
 */
function escapeMarkdown(value: string): string {
  return sanitizeText(String(value)).replace(/[\\`*_[\]<>|~&]/g, (char) => `\\${char}`);
}
