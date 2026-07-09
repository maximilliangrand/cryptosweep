/**
 * Opt-in OSV.dev advisory enrichment for flagged dependencies.
 *
 * This is the only network path in cryptosweep and it is OFF by default (behind
 * `--advisories`). It adds a *distinct* dimension to a dependency finding, known
 * CVE advisories, without ever changing the post-quantum verdict: it only
 * appends references and one recommendation line. It queries OSV.dev only for
 * dependencies that are BOTH already flagged by the registry AND concretely
 * pinned (attaching a CVE to a version the user may not have installed would be
 * a guess). The endpoint is a hard-coded constant, so there is no SSRF surface.
 * Every failure is fail-closed: the original findings are returned unchanged.
 */
import type { Finding, Reference } from "../../report";
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

/** A concretely-pinned version has no open-range operator and is purely numeric. */
function isPinned(version: string | undefined): version is string {
  const v = (version ?? "").trim();
  return /^\d+(?:\.\d+)*$/.test(v);
}

function warn(message: string): void {
  process.stderr.write(`cryptosweep: ${message}\n`);
}

/** One OSV batch POST. Fail-closed: returns [] and warns once on any problem. */
async function queryOsvBatch(queries: OsvQuery[], opts: AdvisoryOptions): Promise<OsvResult[]> {
  if (queries.length === 0) return [];
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
 * Append known-advisory references to already-flagged, pinned dependencies.
 * Pure with respect to the PQ verdict: severity, pq_status, confidence, and
 * title are never touched.
 */
export async function annotateWithAdvisories(
  findings: Finding[],
  deps: readonly ParsedDep[],
  opts: AdvisoryOptions,
): Promise<Finding[]> {
  const byEvidence = new Map<string, ParsedDep>();
  for (const dep of deps) byEvidence.set(`${dep.manifestPath}:${dep.name}@${dep.version || "*"}`, dep);

  const eligible: Array<{ finding: Finding; query: OsvQuery }> = [];
  for (const finding of findings) {
    const dep = byEvidence.get(finding.evidence);
    if (!dep || !isPinned(dep.version)) continue;
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
