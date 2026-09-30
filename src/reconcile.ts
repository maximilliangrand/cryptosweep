/**
 * Cross-engine reconciliation.
 *
 * cryptosweep runs two detectors of very different evidential quality over the
 * same repository: the dependency registry, which knows what a library *can* do,
 * and the AST scanner, which knows what the code *actually calls*. Left
 * unreconciled they contradict each other in the same report — the registry
 * asserting "jsonwebtoken: the RS256/ES256 paths are broken by Shor" at
 * `medium` confidence while the AST has structurally confirmed that every
 * algorithm the package uses is HMAC, which Shor does not touch. A CI gate then
 * fails on a finding the tool itself already disproved at higher confidence.
 *
 * The rule is deliberately narrow, because reconciliation is only sound when
 * the source evidence is decisive:
 *
 *   - it only downgrades, never upgrades (a missed call site must not become a
 *     clean bill of health);
 *   - it only touches a library whose flagged concern is exactly what the
 *     source evidence settles (jsonwebtoken: which JWS algorithms are used).
 *     General toolkits (jsrsasign) and Python or Rust libraries, whose source
 *     is only regex-scanned, are never reconciled;
 *   - it only touches a direct dependency declared in a package.json. A
 *     lockfile entry may be pulled in by another package whose calls the
 *     scanner never saw;
 *   - the evidence is the library's call sites in the source tree that
 *     manifest owns: files under its directory, minus nested packages that
 *     declare the library themselves. At least one call site must be
 *     import-resolved (`confirmed`), every one must pin an HMAC algorithm, and
 *     none may be unsigned or choose its algorithm at runtime;
 *   - nothing is reconciled when the source scan had a gap that could hide a
 *     call site (truncation, unreadable paths, JS/TS files the AST did not
 *     analyse, per-file caps).
 *
 * A downgraded finding cites the call sites that justified it.
 */
import { posix } from "node:path";
import type { Finding } from "./report";

/** Dependency rule, and the source-rule namespace whose call sites settle it. */
const RECONCILABLE: ReadonlyMap<string, { library: string; sites: string }> = new Map([
  ["deps/npm-jsonwebtoken", { library: "jsonwebtoken", sites: "jwt/jsonwebtoken/" }],
]);

/** Call-site rules that leave the library's asymmetric paths out of play. */
const SYMMETRIC_SITE = /\/hmac$/;

/** Source coverage gaps under which the call-site evidence is incomplete. */
const INCOMPLETE_SOURCE: ReadonlySet<string> = new Set([
  "source/scan-truncated",
  "source/unreadable-path",
  "source/ast-fallback",
  "source/findings-capped",
]);

const MAX_CITED_SITES = 5;

function pathOf(finding: Finding): string | null {
  return finding.location?.path ?? null;
}

/** The directory a manifest owns; "" is the scan root. */
function manifestDir(manifestPath: string): string {
  const dir = posix.dirname(manifestPath);
  return dir === "." ? "" : dir;
}

function isUnder(dir: string, path: string): boolean {
  return dir === "" || path.startsWith(`${dir}/`);
}

/** The deepest manifest directory that contains `path`, or null. */
function owningDir(path: string, dirs: readonly string[]): string | null {
  let best: string | null = null;
  for (const dir of dirs) {
    if (isUnder(dir, path) && (best === null || dir.length > best.length)) best = dir;
  }
  return best;
}

/** The call sites justify a downgrade only if they are decisive. */
function isDecisive(sites: readonly Finding[]): boolean {
  if (sites.length === 0) return false;
  if (!sites.some((site) => site.confidence === "confirmed")) return false;
  return sites.every((site) => SYMMETRIC_SITE.test(site.ruleId ?? ""));
}

function describeSites(sites: readonly Finding[]): string {
  const cited = sites.slice(0, MAX_CITED_SITES).map((site) => `${site.algorithm?.replace(/^JWT-/, "") ?? "HMAC"} at ${site.evidence}`);
  const more = sites.length - cited.length;
  return more > 0 ? `${cited.join(", ")}, and ${more} more` : cited.join(", ");
}

function downgrade(finding: Finding, library: string, dir: string, sites: readonly Finding[]): Finding {
  const scope = dir === "" ? "the repository root" : `${dir}/`;
  return {
    ...finding,
    severity: "low",
    pq_status: "transitional",
    confidence: "high",
    recommendation:
      `Source analysis of the package at ${scope} found ${sites.length} ${library} call site(s), every one pinned to HMAC (symmetric), which Shor's algorithm does not break: ${describeSites(sites)}. ` +
      `So ${library}'s asymmetric paths are not in play for this package, and the finding is downgraded from the registry default. Protect and rotate the shared secret, and re-check if RS*/ES*/PS* signing is ever introduced. ${finding.recommendation}`,
  };
}

/**
 * Reconcile dependency findings against confirmed source evidence from the same
 * scan. Returns a new array; inputs are not mutated.
 */
export function reconcile(findings: readonly Finding[]): Finding[] {
  if (findings.some((f) => INCOMPLETE_SOURCE.has(f.ruleId ?? ""))) return [...findings];

  const verdicts = new Map<Finding, Finding>();
  for (const [depRule, { library, sites: sitePrefix }] of RECONCILABLE) {
    const direct = findings.filter((f) => {
      const path = pathOf(f);
      return f.category === "deps" && f.ruleId === depRule && path !== null && posix.basename(path) === "package.json";
    });
    if (direct.length === 0) continue;
    const dirs = [...new Set(direct.map((f) => manifestDir(pathOf(f) ?? "")))];
    const sitesByDir = new Map<string, Finding[]>();
    for (const site of findings) {
      const path = pathOf(site);
      if (!path || !(site.ruleId ?? "").startsWith(sitePrefix)) continue;
      const dir = owningDir(path, dirs);
      if (dir !== null) sitesByDir.set(dir, [...(sitesByDir.get(dir) ?? []), site]);
    }
    for (const dep of direct) {
      const dir = manifestDir(pathOf(dep) ?? "");
      const sites = sitesByDir.get(dir) ?? [];
      if (isDecisive(sites)) verdicts.set(dep, downgrade(dep, library, dir, sites));
    }
  }
  return findings.map((finding) => verdicts.get(finding) ?? finding);
}
