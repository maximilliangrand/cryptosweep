/**
 * SARIF 2.1.0 emitter.
 *
 * SARIF is the lingua franca of static-analysis output: GitHub code scanning,
 * Azure DevOps, and most CI security dashboards ingest it directly. Emitting it
 * is what turns cryptosweep from a report you read into a check that runs on
 * every pull request.
 *
 * One SARIF rule per `Finding.ruleId`, with metadata that depends on the rule
 * id alone, so an alert's description never changes with whichever finding
 * happened to sort first. Each result carries its own level and severity.
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */
import { confidenceOf, ruleIdFromLabel } from "../report";
import type { Finding, Report, Severity } from "../report";
import { entryForRuleId } from "../scanners/deps/registry";
import { SOURCE_RULES } from "../scanners/source-rules";
import { VERSION } from "../version";

/** Canonical home of the project; tool metadata and rule help links point here. */
export const REPOSITORY_URL = "https://github.com/maximilliangrand/cryptosweep";

const SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

/** Repository-relative paths resolve against this base, which code-scanning uploads bind to the checkout root. */
const SOURCE_ROOT = "%SRCROOT%";

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
const SEVERITY_TO_SCORE: Record<Severity, number> = {
  critical: 9.5,
  high: 8.0,
  medium: 5.0,
  low: 3.0,
  info: 0.0,
};

const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

/**
 * Descriptions for the rules the built-in scanners emit: the TLS and
 * dependency-coverage rules here, and every source, JWT and key rule from the
 * source scanner's own catalogue. Anything else is described from its id.
 */
interface RuleText {
  short: string;
  full?: string;
}

const RULE_DESCRIPTIONS: ReadonlyMap<string, RuleText> = new Map<string, RuleText>([
  ["tls/leaf-public-key", { short: "Leaf certificate public key (quantum or classical weakness)" }],
  ["tls/leaf-signature", { short: "Leaf certificate signature algorithm" }],
  ["tls/chain-classical", { short: "Intermediate certificates use classical cryptography" }],
  ["tls/intermediate-signature", { short: "Intermediate certificate signed with a broken or unrecognized algorithm" }],
  ["tls/chain-untrusted", { short: "Certificate chain did not validate" }],
  ["tls/negotiated-protocol", { short: "Negotiated TLS protocol version" }],
  ["tls/hybrid-kex", { short: "Post-quantum key exchange support" }],
  ["tls/leaf-expired", { short: "Leaf certificate has expired" }],
  ["tls/leaf-expiring", { short: "Leaf certificate expires within 30 days" }],
  ["tls/no-leaf", { short: "No leaf certificate could be read" }],
  ["deps/unsupported-manifest", { short: "Dependency files in formats the dependency scan does not parse" }],
  ["deps/manifest-too-large", { short: "Dependency manifests above the size limit were not parsed" }],
  ["deps/scan-truncated", { short: "Dependency scan stopped at a resource limit" }],
  ...SOURCE_RULES.map((rule): [string, RuleText] => [
    rule.id,
    { short: rule.title, full: rule.recommendation },
  ]),
]);

const CATEGORY_NOUN: Readonly<Record<string, string>> = {
  tls: "TLS",
  source: "Source crypto",
  deps: "Dependency",
  jwt: "JSON Web Token",
  keys: "Key material",
};

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  helpUri: string;
  defaultConfiguration: { level: Level };
  properties: { "security-severity": string; category: string; tags: string[] };
}

/**
 * The rule's description, from its id alone: the catalogue, the dependency
 * registry, or the id itself. A rule id that `buildReport` derived from an
 * algorithm (`source/sha-1`) is described by that algorithm's own spelling,
 * which the id determines.
 */
function describeRule(ruleId: string, category: string, findings: readonly Finding[]): RuleText {
  const known = RULE_DESCRIPTIONS.get(ruleId);
  if (known) return known;
  const entry = category === "deps" ? entryForRuleId(ruleId) : undefined;
  if (entry) return { short: `Dependency ${entry.name} (${entry.ecosystem}) uses quantum-relevant cryptography`, full: entry.reason };
  const algorithm = findings.map((f) => f.algorithm).find((a) => a !== undefined && ruleIdFromLabel(category, a) === ruleId);
  const noun = CATEGORY_NOUN[category] ?? category;
  if (algorithm) return { short: `${noun}: ${category === "jwt" ? algorithm.replace(/^jwt-/i, "") : algorithm}` };
  const subject = ruleId.slice(ruleId.indexOf("/") + 1).replace(/[-_]+/g, " ").trim();
  return { short: `${noun}: ${subject || ruleId}` };
}

/**
 * One rule per rule id. Its `security-severity` is the most severe result it
 * has in this run, because GitHub scores every alert of a rule by that one
 * number and a rule must never understate its worst alert; each result also
 * carries its own level, rank and severity.
 */
function ruleFor(ruleId: string, findings: readonly Finding[]): SarifRule {
  const first = findings[0];
  const category = first?.category ?? ruleId.split("/")[0] ?? "finding";
  const worst = SEVERITY_ORDER.find((sev) => findings.some((f) => f.severity === sev)) ?? "info";
  const { short, full } = describeRule(ruleId, category, findings);
  return {
    id: ruleId,
    name: toPascal(ruleId),
    shortDescription: { text: short },
    ...(full ? { fullDescription: { text: full } } : {}),
    helpUri: `${REPOSITORY_URL}#readme`,
    defaultConfiguration: { level: SEVERITY_TO_LEVEL[worst] },
    properties: {
      "security-severity": SEVERITY_TO_SCORE[worst].toFixed(1),
      category,
      tags: ["security", "cryptography", category],
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

interface ArtifactLocation {
  uri: string;
  uriBaseId?: string;
}

interface SarifLocation {
  physicalLocation: { artifactLocation: ArtifactLocation; region?: { startLine: number } };
  logicalLocations?: { name: string; kind: string; fullyQualifiedName: string }[];
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: Level;
  rank: number;
  message: { text: string };
  locations?: SarifLocation[];
  properties: Record<string, string>;
}

/** Characters RFC 3986 allows unescaped in a path segment (`pchar`). */
const PCHAR = /^[A-Za-z0-9\-._~!$&'()*+,;=:@]$/;

/** Percent-encode one path segment; `:` too in the first segment of a relative reference, where it would read as a scheme. */
function encodeSegment(segment: string, isFirst: boolean): string {
  let out = "";
  for (const char of segment) {
    if (PCHAR.test(char) && !(isFirst && char === ":")) {
      out += char;
      continue;
    }
    for (const byte of Buffer.from(char, "utf8")) out += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return out;
}

/** A host as a URI authority: IPv6 literals bracketed, anything outside a DNS name or IP percent-encoded. */
function encodeHost(host: string): string {
  if (host.includes(":")) return `[${host.replace(/[^0-9A-Fa-f:.]/g, (char) => encodeURIComponent(char))}]`;
  return host.replace(/[^A-Za-z0-9.-]/g, (char) => encodeURIComponent(char));
}

/**
 * A file path as a SARIF artifact location. Repository-relative paths become
 * relative URI references against `%SRCROOT%`, the form code scanning anchors
 * to the checkout; an absolute path becomes a `file:` URI instead of being
 * passed off as relative. Separators are normalized and every segment is
 * percent-encoded, so a space, `#` or `?` in a file name cannot truncate or
 * redirect the URI.
 */
function artifactLocationFor(path: string): ArtifactLocation {
  const normalized = path.replace(/\\/g, "/");
  const drive = /^[A-Za-z]:\//.exec(normalized);
  if (normalized.startsWith("/") || drive) {
    const segments = normalized.replace(/^\/+/, "").split("/");
    const encoded = segments.map((segment, i) => (i === 0 && drive ? segment : encodeSegment(segment, false)));
    return { uri: `file:///${encoded.join("/")}` };
  }
  const segments = normalized.replace(/^(?:\.\/)+/, "").split("/").filter((segment) => segment !== "");
  return { uri: segments.map((segment, i) => encodeSegment(segment, i === 0)).join("/"), uriBaseId: SOURCE_ROOT };
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
        artifactLocation: artifactLocationFor(path),
        ...(line ? { region: { startLine: line } } : {}),
      },
    };
  }
  if (host) {
    const authority = host.includes(":") ? `[${host}]` : host;
    const endpoint = port ? `${authority}:${port}` : authority;
    return {
      physicalLocation: { artifactLocation: { uri: `tls://${encodeHost(host)}${port ? `:${port}` : ""}` } },
      logicalLocations: [{ name: endpoint, kind: "resource", fullyQualifiedName: endpoint }],
    };
  }
  return null;
}

function resultFor(finding: Finding, ruleId: string, ruleIndex: number): SarifResult {
  const references = (finding.references ?? []).map((r) => r.label).join("; ");
  const score = SEVERITY_TO_SCORE[finding.severity];
  const result: SarifResult = {
    ruleId,
    ruleIndex,
    level: SEVERITY_TO_LEVEL[finding.severity],
    rank: score * 10,
    message: {
      text: references ? `${finding.title}, ${finding.recommendation} [${references}]` : `${finding.title}, ${finding.recommendation}`,
    },
    properties: {
      severity: finding.severity,
      "security-severity": score.toFixed(1),
      pq_status: finding.pq_status,
      confidence: confidenceOf(finding),
      evidence: finding.evidence,
    },
  };
  const location = locationFor(finding);
  if (location) result.locations = [location];
  return result;
}

/** The rule id a finding reports under; `buildReport` always supplies one. */
function ruleIdOf(finding: Finding): string {
  return finding.ruleId ?? `${finding.category}/${finding.id}`;
}

/** Render a report as a SARIF 2.1.0 log (pretty JSON). */
export function toSarif(report: Report): string {
  const byRule = new Map<string, Finding[]>();
  for (const finding of report.findings) {
    const ruleId = ruleIdOf(finding);
    const bucket = byRule.get(ruleId) ?? [];
    bucket.push(finding);
    byRule.set(ruleId, bucket);
  }
  const ruleIds = [...byRule.keys()].sort();
  const rules = ruleIds.map((id) => ruleFor(id, byRule.get(id) ?? []));
  const indexOf = new Map(ruleIds.map((id, i) => [id, i]));

  const log = {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "cryptosweep",
            version: VERSION,
            semanticVersion: VERSION,
            informationUri: REPOSITORY_URL,
            rules,
          },
        },
        originalUriBaseIds: {
          [SOURCE_ROOT]: { description: { text: "The root of the scanned repository or directory." } },
        },
        results: report.findings.map((finding) => {
          const ruleId = ruleIdOf(finding);
          return resultFor(finding, ruleId, indexOf.get(ruleId) ?? 0);
        }),
        properties: { target: report.target, scanned_at: report.scanned_at },
      },
    ],
  };
  return JSON.stringify(log, null, 2);
}
