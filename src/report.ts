/**
 * Report model shared by every scanner, plus JSON + Markdown serialization.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Category = "tls" | "source" | "deps" | "jwt" | "keys";
export type PqStatus = "vulnerable" | "transitional" | "safe" | "unknown";

export interface Finding {
  id: string;
  severity: Severity;
  category: Category;
  title: string;
  evidence: string;
  pq_status: PqStatus;
  recommendation: string;
}

export interface ReportSummary {
  findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
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
  const summary: ReportSummary = { findings: findings.length, critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) {
    if (finding.severity === "critical") summary.critical += 1;
    else if (finding.severity === "high") summary.high += 1;
    else if (finding.severity === "medium") summary.medium += 1;
    else if (finding.severity === "low") summary.low += 1;
  }
  return summary;
}

/** Build a Report from raw findings, sorting by severity and stamping the scan time. */
export function buildReport(target: string, findings: Finding[], scannedAt: Date = new Date()): Report {
  const sorted = [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
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
      `(critical: ${summary.critical}, high: ${summary.high}, medium: ${summary.medium}, low: ${summary.low})`,
    ``,
  ];

  if (report.findings.length === 0) {
    lines.push(`No quantum-vulnerable primitives detected.`);
    return lines.join("\n");
  }

  lines.push(`| Severity | Category | PQ status | Finding | Evidence |`);
  lines.push(`| --- | --- | --- | --- | --- |`);
  for (const finding of report.findings) {
    lines.push(
      `| ${SEVERITY_BADGE[finding.severity]} | ${finding.category} | ${finding.pq_status} | ` +
        `${escapeCell(finding.title)} | ${escapeCell(finding.evidence)} |`,
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
