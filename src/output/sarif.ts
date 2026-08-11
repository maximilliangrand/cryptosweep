/**
 * SARIF 2.1.0 emitter.
 *
 * SARIF is the lingua franca of static-analysis output: GitHub code scanning,
 * Azure DevOps, and most CI security dashboards ingest it directly. Emitting it
 * is what turns cryptosweep from a report you read into a check that runs on
 * every pull request.
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */
import type { Finding, Report, Severity } from "../report";
import { VERSION } from "../version";

/** SARIF result levels. */
type Level = "error" | "warning" | "note" | "none";

const SEVERITY_TO_LEVEL: Record<Severity, Level> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "none",
};

/** GitHub code scanning reads `security-severity` as a CVSS-like 0.0-10.0 score. */
const SEVERITY_TO_SCORE: Record<Severity, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.0",
  low: "3.0",
  info: "0.0",
};

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  helpUri: string;
  properties: { "security-severity": string; category: string };
}

function ruleFor(finding: Finding): SarifRule {
  return {
    id: finding.ruleId ?? `${finding.category}/${finding.id}`,
    name: toPascal(finding.ruleId ?? finding.id),
    shortDescription: { text: finding.title },
    helpUri: "https://github.com/Grandillionaire/cryptosweep#readme",
    properties: {
      "security-severity": SEVERITY_TO_SCORE[finding.severity],
      category: finding.category,
    },
  };
}

function toPascal(id: string): string {
  return id
    .split(/[^a-z0-9]+/i)
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join("");
}

interface SarifLocation {
  physicalLocation: { artifactLocation: { uri: string }; region?: { startLine: number } };
  logicalLocations?: { name: string; kind: string; fullyQualifiedName: string }[];
}

interface SarifResult {
  ruleId: string;
  level: Level;
  message: { text: string };
  locations?: SarifLocation[];
  properties: Record<string, string>;
}

/**
 * Where a finding happened, in SARIF terms.
 *
 * Every result needs one: GitHub code scanning anchors alerts to a location and
 * drops (or roots) results without one, so a location-less TLS finding is a
 * finding nobody ever sees. A network probe has no file, so its host:port is
 * expressed as a `tls://` artifact plus a logical location naming the endpoint.
 */
function locationFor(finding: Finding): SarifLocation | null {
  const { path, line, host, port } = finding.location ?? {};
  if (path) {
    return {
      physicalLocation: {
        artifactLocation: { uri: path },
        ...(line ? { region: { startLine: line } } : {}),
      },
    };
  }
  if (host) {
    const endpoint = port ? `${host}:${port}` : host;
    return {
      physicalLocation: { artifactLocation: { uri: `tls://${endpoint}` } },
      logicalLocations: [{ name: endpoint, kind: "resource", fullyQualifiedName: endpoint }],
    };
  }
  return null;
}

function resultFor(finding: Finding): SarifResult {
  const ruleId = finding.ruleId ?? `${finding.category}/${finding.id}`;
  const references = (finding.references ?? []).map((r) => r.label).join("; ");
  const result: SarifResult = {
    ruleId,
    level: SEVERITY_TO_LEVEL[finding.severity],
    message: {
      text: references ? `${finding.title}, ${finding.recommendation} [${references}]` : `${finding.title}, ${finding.recommendation}`,
    },
    properties: {
      severity: finding.severity,
      pq_status: finding.pq_status,
      confidence: finding.confidence ?? "medium",
      evidence: finding.evidence,
    },
  };
  const location = locationFor(finding);
  if (location) result.locations = [location];
  return result;
}

/** Render a report as a SARIF 2.1.0 log (pretty JSON). */
export function toSarif(report: Report): string {
  const rules = new Map<string, SarifRule>();
  for (const finding of report.findings) {
    const rule = ruleFor(finding);
    if (!rules.has(rule.id)) rules.set(rule.id, rule);
  }

  const log = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "cryptosweep",
            version: VERSION,
            informationUri: "https://github.com/Grandillionaire/cryptosweep",
            rules: [...rules.values()],
          },
        },
        results: report.findings.map(resultFor),
        properties: { target: report.target, scanned_at: report.scanned_at },
      },
    ],
  };
  return JSON.stringify(log, null, 2);
}
