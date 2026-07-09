/**
 * Report model shared by every scanner, plus JSON + Markdown serialization.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Category = "tls" | "source" | "deps" | "jwt" | "keys";
export type PqStatus = "vulnerable" | "transitional" | "safe" | "unknown";

/**
 * How sure the scanner is that a finding is real and correctly classified.
 *
 * - `confirmed` — derived from parsed, structured evidence (an ASN.1 field, a
 *   `KeyObject`, a resolved dependency version). No guessing.
 * - `high` — a strong structural signal with a small, well-understood residual
 *   ambiguity.
 * - `medium` — a heuristic (regex) match on code with real false-positive risk.
 * - `low` — a match in a context (docs, tests, examples) where it may not be a
 *   live code path at all.
 */
export type Confidence = "confirmed" | "high" | "medium" | "low";

/** A citation backing a finding — a standard, advisory, or spec. */
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

export interface Finding {
  /** Human-facing, per-report sequential id, e.g. `CSW-TLS-001`. */
  id: string;
  /**
   * Stable rule identity shared by every finding of the same kind, e.g.
   * `tls/leaf-key-quantum-vulnerable`. Drives SARIF `ruleId` and CBOM grouping.
   * Optional at construction; {@link buildReport} derives one from `id` when absent.
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
  recommendation: string;
  /** Standards / advisories backing the classification. */
  references?: Reference[];
}

export interface ReportSummary {
  findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface Report {
  target: string;
  scanned_at: string;
  summary: ReportSummary;
  findings: Finding[];
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
 * Fill in ontology defaults so every downstream consumer (CBOM, SARIF, the
 * viewer) can rely on `ruleId` and `confidence` being present. A scanner may
 * set them explicitly; this only supplies a default when it did not.
 */
export function normalizeFinding(finding: Finding): Required<Pick<Finding, "ruleId" | "confidence">> & Finding {
  return {
    ...finding,
    ruleId: finding.ruleId ?? deriveRuleId(finding),
    confidence: finding.confidence ?? "medium",
  };
}

/** Derive a stable rule id from a finding when a scanner did not provide one. */
function deriveRuleId(finding: Finding): string {
  const base = finding.id.replace(/-\d+$/, "").toLowerCase().replace(/[^a-z0-9]+/g, "-");
  return `${finding.category}/${base || "finding"}`;
}

/** Build a Report from raw findings, sorting by severity and stamping the scan time. */
export function buildReport(target: string, findings: Finding[], scannedAt: Date = new Date()): Report {
  const normalized = findings.map(normalizeFinding);
  const sorted = normalized.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  return {
    target,
    scanned_at: scannedAt.toISOString(),
    summary: summarize(sorted),
    findings: sorted,
  };
}

/** Serialize a report as pretty-printed JSON. */
export function toJson(report: Report): string {
  return JSON.stringify(report, null, 2);
}

const SEVERITY_BADGE: Record<Severity, string> = {
  critical: "🟥 critical",
  high: "🟧 high",
  medium: "🟨 medium",
  low: "🟦 low",
  info: "⬜ info",
};

/** Render a report as a human-readable Markdown summary. */
export function toMarkdown(report: Report): string {
  const { summary } = report;
  const lines: string[] = [
    `# cryptosweep report`,
    ``,
    `- **Target:** ${report.target}`,
    `- **Scanned at:** ${report.scanned_at}`,
    `- **Findings:** ${summary.findings} ` +
      `(critical: ${summary.critical}, high: ${summary.high}, medium: ${summary.medium}, ` +
      `low: ${summary.low}, info: ${summary.info})`,
    ``,
  ];

  if (report.findings.length === 0) {
    lines.push(`No quantum-vulnerable primitives detected.`);
    return lines.join("\n");
  }

  lines.push(`| Severity | Category | PQ status | Confidence | Finding | Evidence |`);
  lines.push(`| --- | --- | --- | --- | --- | --- |`);
  for (const finding of report.findings) {
    lines.push(
      `| ${SEVERITY_BADGE[finding.severity]} | ${finding.category} | ${finding.pq_status} | ` +
        `${finding.confidence ?? "medium"} | ${escapeCell(finding.title)} | ${escapeCell(finding.evidence)} |`,
    );
  }

  lines.push(``, `## Recommendations`, ``);
  for (const finding of report.findings) {
    lines.push(`- **${finding.id}** — ${finding.recommendation}`);
  }

  return lines.join("\n");
}

function escapeCell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\n/g, " ");
}
