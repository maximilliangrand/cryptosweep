/**
 * Opt-in OSV.dev advisory enrichment for flagged dependencies.
 *
 * This is the only network call the dependency scanner makes, and it is OFF by
 * default (behind `--advisories`; on the MCP server, the operator's
 * CRYPTOSWEEP_MCP_ADVISORIES). TLS scans and GitHub clones are network
 * operations by nature and go through the SSRF guard instead. It adds a *distinct* dimension to a dependency finding, known
 * CVE advisories, without ever changing the post-quantum verdict: it only
 * appends references and one recommendation line. It queries OSV.dev only for
 * dependencies that are BOTH already flagged by the registry AND concretely
 * pinned (attaching a CVE to a version the user may not have installed would be
 * a guess). The endpoint is a hard-coded constant, so there is no SSRF surface.
 * Every failure is fail-closed: the original findings are returned unchanged.
 */
import type { Finding, Reference } from "../../report";
import { entryForRuleId } from "./registry";
import type { Ecosystem } from "./registry";
import type { ParsedDep } from "./parsers/npm";

const OSV_ENDPOINT = "https://api.osv.dev/v1/querybatch";
const MAX_ADVISORIES_PER_FINDING = 5;

/** Minimal fetch shape, so tests can inject a stub without a real network. */
type FetchLike = (
  input: string,
  init: { method: string; headers: Record<string, string>; body: string; signal: AbortSignal },
) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }>;

export interface AdvisoryOptions {
  enabled: boolean;
  /** Injected in tests; defaults to the global fetch. */
  fetchImpl?: FetchLike;
  /** Overridable in tests; defaults to the OSV endpoint constant. */
  endpoint?: string;
  timeoutMs?: number;
  /** Where lookup failures are reported; defaults to stderr. MCP and library callers can capture them. */
  onWarning?: (message: string) => void;
}

/** cryptosweep ecosystem -> OSV ecosystem name. Anything unmapped is skipped. */
export const ECOSYSTEM_TO_OSV: Readonly<Record<Ecosystem, string>> = {
  npm: "npm",
  python: "PyPI",
  cargo: "crates.io",
};

interface OsvQuery {
  package: { name: string; ecosystem: string };
  version: string;
}
interface OsvResult {
  vulns?: Array<{ id?: string }>;
}

/**
 * A concretely-pinned dependency: a purely numeric version, and no wider
 * constraint behind it. A Python `>=41` keeps only `41` as its version, and a
 * Cargo `0.23.27` is a caret range; neither names the installed release.
 */
function isPinned(dep: ParsedDep): boolean {
  if (!/^\d+(?:\.\d+)*$/.test(dep.version.trim())) return false;
  return dep.constraint === undefined || /^={2,3}\s*\d+(?:\.\d+)*$/.test(dep.constraint.trim());
}

function stderrWarning(message: string): void {
  process.stderr.write(`cryptosweep: ${message}\n`);
}

/** One OSV batch POST. Fail-closed: returns [] and warns once on any problem. */
async function queryOsvBatch(queries: OsvQuery[], opts: AdvisoryOptions): Promise<OsvResult[]> {
  if (queries.length === 0) return [];
  const warn = opts.onWarning ?? stderrWarning;
  const doFetch = opts.fetchImpl ?? (fetch as unknown as FetchLike);
  try {
    const res = await doFetch(opts.endpoint ?? OSV_ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ queries }),
      signal: AbortSignal.timeout(opts.timeoutMs ?? 5000),
    });
    if (!res.ok) {
      warn(`OSV advisory lookup failed (HTTP ${res.status}); reporting PQ findings only.`);
      return [];
    }
    const data = (await res.json()) as { results?: OsvResult[] };
    return data.results ?? [];
  } catch (err) {
    warn(`OSV advisory lookup failed (${err instanceof Error ? err.message : String(err)}); reporting PQ findings only.`);
    return [];
  }
}

/**
 * The parsed dependency a finding is about, joined on structured identity:
 * ecosystem and name (from `Finding.dependency`, or the registry entry its rule
 * id names) plus the manifest path, and the declared version when the finding
 * carries one. Rebuilding the evidence string to look a dependency up tied this
 * module to another module's display format. When the finding carries no
 * version and one manifest lists the package twice, the join is ambiguous and
 * the finding is skipped, which fails closed.
 */
function dependencyOf(finding: Finding, deps: readonly ParsedDep[]): ParsedDep | undefined {
  if (finding.category !== "deps") return undefined;
  const entry = entryForRuleId(finding.ruleId);
  const ecosystem = finding.dependency?.ecosystem ?? entry?.ecosystem;
  const name = finding.dependency?.name ?? entry?.name;
  if (!ecosystem || !name) return undefined;
  const manifestPath = finding.location?.path;
  const candidates = deps.filter(
    (dep) =>
      dep.ecosystem === ecosystem &&
      dep.name === name &&
      (manifestPath === undefined || dep.manifestPath === manifestPath) &&
      (finding.dependency?.version === undefined || dep.version === finding.dependency.version),
  );
  const versions = new Set(candidates.map((dep) => dep.version));
  return versions.size === 1 ? candidates[0] : undefined;
}

/**
 * Append known-advisory references to already-flagged, pinned dependencies.
 * Pure with respect to the PQ verdict: severity, pq_status, confidence, and
 * title are never touched.
 */
export async function annotateWithAdvisories(
  findings: Finding[],
  deps: readonly ParsedDep[],
  opts: AdvisoryOptions,
): Promise<Finding[]> {
  const eligible: Array<{ finding: Finding; query: OsvQuery }> = [];
  for (const finding of findings) {
    const dep = dependencyOf(finding, deps);
    if (!dep || !isPinned(dep)) continue;
    const ecosystem = ECOSYSTEM_TO_OSV[dep.ecosystem];
    if (!ecosystem) continue;
    eligible.push({ finding, query: { package: { name: dep.name, ecosystem }, version: dep.version } });
  }
  if (eligible.length === 0) return findings;

  const results = await queryOsvBatch(
    eligible.map((e) => e.query),
    opts,
  );

  const annotated = new Map<Finding, Finding>();
  eligible.forEach((entry, i) => {
    const vulns = results[i]?.vulns ?? [];
    const ids = [...new Set(vulns.map((v) => v.id).filter((id): id is string => Boolean(id)))]
      .sort()
      .slice(0, MAX_ADVISORIES_PER_FINDING);
    if (ids.length === 0) return;
    const advisoryRefs: Reference[] = ids.map((id) => ({
      label: `${id}, known advisory (OSV.dev, not PQ-specific)`,
      url: `https://osv.dev/vulnerability/${id}`,
    }));
    annotated.set(entry.finding, {
      ...entry.finding,
      references: [...(entry.finding.references ?? []), ...advisoryRefs],
      recommendation: `${entry.finding.recommendation} Known advisories (not PQ): ${ids.join(", ")}.`,
    });
  });

  return findings.map((f) => annotated.get(f) ?? f);
}
