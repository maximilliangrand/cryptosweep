/**
 * Cross-engine reconciliation.
 *
 * cryptosweep runs two detectors of very different evidential quality over the
 * same repository: the dependency registry, which knows what a library *can* do,
 * and the AST scanner, which knows what the code *actually calls*. Left
 * unreconciled they contradict each other in the same report — the registry
 * asserting "jsonwebtoken: the RS256/ES256 paths are broken by Shor" at
 * `medium` confidence while the AST has structurally confirmed that every
 * algorithm in the codebase is HMAC, which Shor does not touch. A CI gate then
 * fails on a finding the tool itself already disproved at higher confidence.
 *
 * The rule here is deliberately narrow, because reconciliation is only sound
 * when the source evidence is decisive:
 *
 *   - it only downgrades, never upgrades (a missed call site must not become a
 *     clean bill of health);
 *   - it only fires on `confirmed` source evidence, i.e. an import-resolved AST
 *     match, never a regex guess;
 *   - it only applies to libraries whose flagged concern is exactly the thing
 *     the source evidence settles.
 */
import type { Finding } from "./report";

/**
 * Dependencies flagged for their asymmetric JWT signing paths. For these, the
 * set of algorithms actually passed to sign/verify is the whole question.
 */
const JWT_LIBRARIES: ReadonlySet<string> = new Set(["jsonwebtoken", "pyjwt", "python-jose", "jsrsasign"]);

/** The library name inside a `deps/<ecosystem>-<name>` rule id. */
function depName(ruleId: string | undefined): string | null {
  const match = /^deps\/(?:npm|python|cargo)-(.+)$/.exec(ruleId ?? "");
  return match?.[1] ?? null;
}

/** True when the AST confirmed JWT algorithms and every one of them is symmetric. */
function onlySymmetricJwtConfirmed(findings: readonly Finding[]): boolean {
  const confirmed = findings.filter(
    (f) => f.category === "jwt" && f.confidence === "confirmed" && f.algorithm?.startsWith("JWT-"),
  );
  if (confirmed.length === 0) return false;
  return confirmed.every((f) => f.algorithm?.startsWith("JWT-HS") === true);
}

/**
 * Reconcile dependency findings against confirmed source evidence from the same
 * scan. Returns a new array; inputs are not mutated.
 */
export function reconcile(findings: readonly Finding[]): Finding[] {
  if (!onlySymmetricJwtConfirmed(findings)) return [...findings];

  return findings.map((finding) => {
    if (finding.category !== "deps") return finding;
    const name = depName(finding.ruleId);
    if (!name || !JWT_LIBRARIES.has(name)) return finding;
    return {
      ...finding,
      severity: "low",
      pq_status: "transitional",
      confidence: "high",
      recommendation:
        `Source analysis confirmed that every JWT algorithm used in this codebase is HMAC (symmetric), which Shor's algorithm does not break, so ${name}'s asymmetric paths are not in play here. ` +
        `Downgraded from the registry default. Protect and rotate the shared secret, and re-check if RS*/ES*/PS* signing is ever introduced. ${finding.recommendation}`,
    };
  });
}
