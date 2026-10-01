/**
 * Crypto-agility risk engine.
 *
 * Projects a scan Report + an EstateProfile into three things a scanner cannot:
 *   1. a Mosca-clock verdict per cryptographic asset (is it already too late?),
 *   2. a harvest-exposure ledger (the growing confidentiality liability), and
 *   3. an ontology graph linking assets -> system -> data class -> obligations.
 *
 * The threat model is not one-size-fits-all, on purpose, and it is decided from
 * structured finding fields (usage, rule id, algorithm, category), never from
 * titles:
 *   - harvest-now: confidentiality crypto (key establishment, encryption). An
 *     adversary recording today decrypts once a CRQC exists, so the deadline is
 *     pulled *backward* by the data's secrecy horizon. This is the only thing
 *     in the harvest ledger.
 *   - forge-later: signatures / authentication. No retroactive harvest; the
 *     deadline is simply "migrate before the CRQC".
 *   - classical: broken today, independent of quantum (MD5 / SHA-1 / DES / RC4,
 *     JWT `alg: none`, sub-floor key sizes, a committed private key). On the
 *     board as "act now", never on the quantum clock and never in the ledger.
 *
 * A primitive whose use the evidence does not pin down (an RSA key could sign
 * or decrypt) is assessed under both quantum threat models and gets the more
 * urgent verdict, and its rationale says so.
 */
import { algorithmUsage } from "../algorithms";
import { cnsa2Standing } from "../crypto";
import type { CryptoUsage, Finding, PqStatus, Severity } from "../report";
import { normalizeFinding } from "../report";
import { entryForRuleId } from "../scanners/deps/registry";
import { assertProfileUsable } from "./estate";
import type { DataClass, EstateProfile, Obligation, ObligationScope } from "./estate";

export type ThreatModel = "harvest-now" | "forge-later" | "classical" | "not-applicable";
export type MoscaStatus = "exposed" | "overdue" | "on-track" | "act-now" | "not-applicable";

export interface MoscaVerdict {
  threat: ThreatModel;
  status: MoscaStatus;
  /** X: years the data must stay secret (only meaningful for harvest-now). */
  horizonYears: number;
  /** Y: estimated migration time in years. */
  migrationYears: number;
  /** Z: assumed CRQC year. */
  crqcYear: number;
  /** Years from `today` until the CRQC. */
  yearsToCrqc: number;
  /** Years from `today` by which migration must COMPLETE (may be negative). */
  mustCompleteInYears: number;
  /** Years from `today` by which migration must START. */
  mustStartInYears: number;
  rationale: string;
}

export interface CryptoAsset {
  key: string;
  label: string;
  category: string;
  /** The rule every finding of this asset shares. */
  ruleId: string;
  /** What the asset is used for, as far as the evidence shows; empty when undetermined. */
  usage: CryptoUsage[];
  pq_status: PqStatus;
  /**
   * Whether the asset uses a public-key algorithm CNSA 2.0 specifies; false
   * when any of its findings uses another one, absent when it is not a
   * public-key primitive or the evidence does not say.
   */
  cnsa2?: boolean;
  worstSeverity: Severity;
  findingIds: string[];
  verdict: MoscaVerdict;
}

export interface HarvestLedger {
  /** Production assets; every count below is over these. */
  totalAssets: number;
  /** Assets seen only in documentation, tests, fixtures or examples, which no count includes. */
  nonProductionAssets: number;
  exposedAssets: number;
  overdueAssets: number;
  actNowAssets: number;
  onTrackAssets: number;
  /**
   * Headline liability: sum over harvest-now-EXPOSED assets of
   * (confidentiality horizon years * data sensitivity). Unit: sensitivity-weighted
   * risk-years. Transparent by construction — no magic number.
   */
  exposureRiskYears: number;
  headline: string;
  byObligation: Array<{ obligation: string; assets: number }>;
}

export interface GraphNode {
  id: string;
  type: "asset" | "system" | "data-class" | "obligation";
  label: string;
  props?: Record<string, string | number>;
}
export interface GraphEdge {
  from: string;
  to: string;
  rel: string;
}
export interface CryptoGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface RiskModel {
  target: string;
  assumptions: {
    today: string;
    crqcYear: number;
    crqcBasis: string;
    dataClass: string;
    horizonYears: number;
    /** Mosca's Y as applied, with where the numbers come from. */
    migrationYears: EstateProfile["migrationYears"];
  };
  assets: CryptoAsset[];
  /**
   * Assets whose every finding sits in documentation, tests, fixtures or
   * examples (`Location.context`). Their verdicts are computed the same way,
   * but they stay out of the ledger, the obligation counts and the graph: a
   * README table or a test fixture is not the estate's exposure.
   */
  nonProductionAssets: CryptoAsset[];
  ledger: HarvestLedger;
  graph: CryptoGraph;
}

/** The threat analysis of one finding, before any profile is applied. */
export interface ThreatAssessment {
  /** Threat models that apply, most urgent first; empty when not applicable. */
  threats: Exclude<ThreatModel, "not-applicable">[];
  /** Resolved usage; empty when the evidence does not determine it. */
  usage: CryptoUsage[];
  /** Why the finding is classically broken, when it is. */
  classicalReason?: string;
  /** True when the usage was undetermined and both quantum threat models were assumed. */
  usageAssumed: boolean;
}

type UsageRow = readonly [pattern: RegExp, usage: readonly CryptoUsage[]];

/**
 * Usage of each rule the scanners emit, by exact rule id. A scanner that knows
 * better sets `Finding.usage`, which wins; a new rule gets a row here (or in
 * {@link USAGE_BY_RULE_FAMILY}), never a title match.
 */
const USAGE_BY_RULE: Readonly<Record<string, readonly CryptoUsage[]>> = {
  "tls/hybrid-kex": ["key-establishment"],
  // In TLS 1.3 the leaf key only authenticates the handshake (CertificateVerify).
  // A scanner that observes static-RSA key transport sets usage explicitly.
  "tls/leaf-public-key": ["authentication"],
  "tls/leaf-signature": ["signature"],
  "tls/chain-classical": ["signature"],
  "tls/intermediate-signature": ["signature"],
  "tls/negotiated-protocol": ["protocol"],
};

/** Rule-id families, for rules whose id carries a variant (e.g. `keys/private-key-block`). */
const USAGE_BY_RULE_FAMILY: readonly UsageRow[] = [
  [/^keys\/(?:[a-z0-9-]*-)?private-key/, ["secret-material"]],
  [/^jwt\//, ["authentication"]],
];

/**
 * Which quantum threat each usage exposes. A quantum-vulnerable protocol
 * finding means classical key exchange was negotiated (an obsolete version is
 * caught earlier as a classical break). Hashing and key material carry no Shor
 * exposure of their own.
 */
const THREATS_BY_USAGE: Readonly<Record<CryptoUsage, readonly ("harvest-now" | "forge-later")[]>> = {
  "key-establishment": ["harvest-now"],
  encryption: ["harvest-now"],
  protocol: ["harvest-now"],
  signature: ["forge-later"],
  authentication: ["forge-later"],
  hashing: [],
  "secret-material": [],
};

/**
 * Algorithms broken classically, today. Matched against the canonical
 * algorithm label only, so `md5WithRSAEncryption` and `ecdsaWithSHA1` (signature
 * OID names) are caught as well as `MD5` and `SHA-1`.
 */
const CLASSICAL_BREAKS: readonly { algorithm: RegExp; reason: string }[] = [
  {
    algorithm: /md[245](?![0-9])/i,
    reason: "MD2/MD4/MD5 are collision-broken (a rogue CA certificate was forged with an MD5 chosen-prefix collision in 2008)",
  },
  {
    algorithm: /sha-?1(?![0-9])/i,
    reason: "SHA-1 has practical chosen-prefix collisions and SP 800-131A disallows it for signatures",
  },
  {
    algorithm: /(?:^|[^a-z])(?:tripledes|desede|desx|3des|des|arcfour|arc4|rc2|rc4)(?![a-z])/i,
    reason: "DES/3DES/RC2/RC4 are broken or deprecated ciphers (key size, 64-bit blocks, keystream biases)",
  },
  { algorithm: /^jwt-none$/i, reason: 'JWT "alg: none" disables signature verification, so any token is accepted' },
];

const SECRET_MATERIAL_REASON = "private key material committed to a repository is compromised on disclosure, whatever its algorithm";
const OBSOLETE_PROTOCOL_REASON = "protocol versions below TLS 1.2 are deprecated (RFC 8996)";

/**
 * Key labels below the SP 800-131A classical minimum (RSA/DSA and finite-field
 * DH < 2048 bits, ECC < 224-bit curve). These are broken without a quantum
 * computer, so they belong on the act-now board, not on the Mosca clock.
 *
 * This is the fallback for findings built without a `classicalBreak` (a
 * library caller's own findings); the scanners set that field from the
 * parameters they parsed, so their verdict never depends on a label parse.
 */
function isClassicallyWeakLabel(algorithm: string | undefined): boolean {
  if (!algorithm) return false;
  const integer = /^(?:rsa|rsa-pss|dsa|dhe?|ffdhe)-(\d+)$/i.exec(algorithm);
  if (integer?.[1]) return Number(integer[1]) < 2048;
  const elliptic = /^(?:ecdsa|ecdhe?)-(?:p-|prime|secp|sect|brainpoolp)?(\d+)/i.exec(algorithm);
  if (elliptic?.[1]) return Number(elliptic[1]) < 224;
  return false;
}

/** Resolve what a finding's primitive is used for, from structured fields only. */
export function resolveUsage(finding: Finding): CryptoUsage[] {
  if (finding.usage && finding.usage.length > 0) return [...finding.usage];
  const ruleId = finding.ruleId ?? "";
  const byRule = USAGE_BY_RULE[ruleId] ?? USAGE_BY_RULE_FAMILY.find(([pattern]) => pattern.test(ruleId))?.[1];
  if (byRule) return [...byRule];
  if (finding.category === "deps") {
    const entry = entryForRuleId(ruleId);
    if (entry) return [...entry.usage];
  }
  return finding.algorithm ? algorithmUsage(finding.algorithm) : [];
}

/**
 * The reason a finding is broken classically today, or undefined.
 *
 * Committed key material is compromised whatever the scanner says about it,
 * and a scanner that parsed sub-floor parameters says so in `classicalBreak`.
 * Otherwise an algorithm is a present-day break only where the scanner flagged
 * it: a scanner that finds SHA-1 computing an ETag or inside HMAC reports it
 * with a `pq_status` other than `vulnerable`, because nothing there relies on
 * the collision resistance that is broken, and that finding stays off the board.
 */
function classicalBreak(finding: Finding, usage: readonly CryptoUsage[]): string | undefined {
  if (usage.includes("secret-material")) return SECRET_MATERIAL_REASON;
  if (finding.classicalBreak) return finding.classicalBreak;
  if (finding.pq_status !== "vulnerable") return undefined;
  const algorithm = finding.algorithm ?? "";
  const hit = CLASSICAL_BREAKS.find((row) => row.algorithm.test(algorithm));
  if (hit) return hit.reason;
  if (isClassicallyWeakLabel(finding.algorithm)) {
    return "the key or group is below the SP 800-131A minimum (RSA, DSA and finite-field DH 2048 bits, ECC 224-bit curves)";
  }
  const version = finding.protocol?.version;
  if (finding.protocol?.type === "tls" && version && /^1(?:\.[01])?$/.test(version)) return OBSOLETE_PROTOCOL_REASON;
  return undefined;
}

/** Analyze one finding's threat models from its structured fields. */
export function assessThreat(raw: Finding): ThreatAssessment {
  const finding = normalizeFinding(raw);
  const usage = resolveUsage(finding);
  const classicalReason = classicalBreak(finding, usage);
  if (classicalReason) return { threats: ["classical"], usage, classicalReason, usageAssumed: false };
  if (finding.pq_status !== "vulnerable") return { threats: [], usage, usageAssumed: false };

  const threats = new Set<"harvest-now" | "forge-later">();
  for (const u of usage) for (const threat of THREATS_BY_USAGE[u]) threats.add(threat);
  if (threats.size === 0) {
    return { threats: ["harvest-now", "forge-later"], usage, usageAssumed: true };
  }
  const ordered = (["harvest-now", "forge-later"] as const).filter((t) => threats.has(t));
  return { threats: [...ordered], usage, usageAssumed: false };
}

/** Classify a cryptographic asset into its primary (most urgent) threat model. */
export function classifyThreat(finding: Finding): ThreatModel {
  return assessThreat(finding).threats[0] ?? "not-applicable";
}

function fractionalYear(iso: string): number {
  const date = new Date(iso);
  const year = date.getUTCFullYear();
  const start = Date.UTC(year, 0, 1);
  const nextYear = Date.UTC(year + 1, 0, 1);
  return year + (date.getTime() - start) / (nextYear - start);
}

function migrationYearsFor(threat: ThreatModel, category: string, profile: EstateProfile): number {
  const { byCategory, byThreat, default: fallback } = profile.migrationYears;
  const perThreat = threat === "harvest-now" || threat === "forge-later" ? byThreat?.[threat] : undefined;
  return byCategory[category] ?? perThreat ?? fallback;
}

const years = (value: number): string => value.toFixed(1);

function verdict(threat: ThreatModel, category: string, profile: EstateProfile, classicalReason?: string): MoscaVerdict {
  const today = fractionalYear(profile.today);
  const crqcYear = profile.quantum.crqcYear;
  const yearsToCrqc = crqcYear - today;
  const migrationYears = migrationYearsFor(threat, category, profile);
  const horizonYears = profile.dataClass.horizonYears;
  const base = { threat, migrationYears, crqcYear, yearsToCrqc, horizonYears };
  const z = `Z = ${years(yearsToCrqc)} years to the assumed CRQC (~${crqcYear})`;

  if (threat === "not-applicable") {
    return { ...base, status: "not-applicable", mustCompleteInYears: NaN, mustStartInYears: NaN, rationale: "Not quantum-vulnerable." };
  }
  if (threat === "classical") {
    return {
      ...base,
      status: "act-now",
      mustCompleteInYears: 0,
      mustStartInYears: 0,
      rationale: `Broken today, independent of the quantum timeline: ${classicalReason ?? "classically weak primitive"}. Remediate now.`,
    };
  }
  if (threat === "harvest-now") {
    if (horizonYears <= 0) {
      return { ...base, status: "not-applicable", mustCompleteInYears: NaN, mustStartInYears: NaN, rationale: "Public data has no confidentiality horizon to protect." };
    }
    const mustCompleteInYears = yearsToCrqc - horizonYears;
    const mustStartInYears = mustCompleteInYears - migrationYears;
    const xyz = `X = ${years(horizonYears)} (secrecy horizon), Y = ${years(migrationYears)} (migration), ${z}`;
    if (mustCompleteInYears < 0) {
      return {
        ...base,
        status: "exposed",
        mustCompleteInYears,
        mustStartInYears,
        rationale: `X > Z: data recorded today is still secret when a CRQC can decrypt it, so harvest-now-decrypt-later exposure is already accruing (${xyz}).`,
      };
    }
    if (mustStartInYears < 0) {
      return {
        ...base,
        status: "overdue",
        mustCompleteInYears,
        mustStartInYears,
        rationale: `X + Y > Z: migration needed to start ${years(-mustStartInYears)} year(s) ago to finish before harvested data becomes decryptable (${xyz}).`,
      };
    }
    return {
      ...base,
      status: "on-track",
      mustCompleteInYears,
      mustStartInYears,
      rationale: `X + Y <= Z: begin within ${years(mustStartInYears)} year(s) and complete within ${years(mustCompleteInYears)} to stay ahead of harvest-now-decrypt-later (${xyz}).`,
    };
  }
  // forge-later: no harvest window; must simply migrate before the CRQC.
  const mustCompleteInYears = yearsToCrqc;
  const mustStartInYears = yearsToCrqc - migrationYears;
  const yz = `Y = ${years(migrationYears)} (migration), ${z}; the secrecy horizon X does not apply to signatures`;
  const status: MoscaStatus = yearsToCrqc <= 0 ? "exposed" : mustStartInYears < 0 ? "overdue" : "on-track";
  const rationale =
    status === "on-track"
      ? `Signature/identity crypto, forgeable once a CRQC exists: begin migration within ${years(mustStartInYears)} year(s) (${yz}).`
      : status === "overdue"
        ? `Y > Z: signature/identity migration needed to start ${years(-mustStartInYears)} year(s) ago to rotate before a CRQC enables forgery (${yz}).`
        : `The assumed CRQC year has passed: signatures and identity keys are forgeable now (${yz}).`;
  return { ...base, status, mustCompleteInYears, mustStartInYears, rationale };
}

/** Lower is more urgent. */
const STATUS_URGENCY: Record<MoscaStatus, number> = { "act-now": 0, exposed: 0, overdue: 1, "on-track": 2, "not-applicable": 3 };

/** The most urgent verdict over every threat model the assessment says applies. */
function worstVerdict(assessment: ThreatAssessment, category: string, profile: EstateProfile): MoscaVerdict {
  const candidates = assessment.threats.length > 0 ? assessment.threats : (["not-applicable"] as const);
  let worst: MoscaVerdict | undefined;
  for (const threat of candidates) {
    const next = verdict(threat, category, profile, assessment.classicalReason);
    if (!worst || STATUS_URGENCY[next.status] < STATUS_URGENCY[worst.status]) worst = next;
  }
  const chosen = worst ?? verdict("not-applicable", category, profile);
  if (!assessment.usageAssumed || chosen.status === "not-applicable") return chosen;
  return {
    ...chosen,
    rationale: `Usage undetermined (key establishment or signature), so assessed under both threat models; the more urgent applies. ${chosen.rationale}`,
  };
}

/**
 * Group findings into distinct cryptographic assets: one per rule and
 * algorithm, so a committed private key and an embedded public key, or an MD5
 * hash and an RC4 cipher, never share an asset.
 */
function assetKey(f: Finding & { ruleId: string }): string {
  return f.algorithm ? `${f.ruleId}:${f.algorithm}` : f.ruleId;
}

function assetLabel(f: Finding & { ruleId: string }, usage: readonly CryptoUsage[]): string {
  if (usage.includes("secret-material")) {
    return f.algorithm ? `Committed private key material (${f.algorithm})` : "Committed private key material";
  }
  if (f.algorithm) return f.algorithm;
  const entry = f.category === "deps" ? entryForRuleId(f.ruleId) : undefined;
  if (entry) return `${entry.name} (${entry.ecosystem})`;
  return f.title;
}

const PQ_RANK: Record<PqStatus, number> = { vulnerable: 0, transitional: 1, unknown: 2, safe: 3 };
const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** Usages that mean a public-key primitive (a hash or a MAC is neither, and CNSA 2.0's symmetric rules are not assessed). */
const PUBLIC_KEY_USAGE: ReadonlySet<CryptoUsage> = new Set<CryptoUsage>(["key-establishment", "signature", "authentication"]);

/**
 * A finding's CNSA 2.0 standing: the scanner's own verdict when it gave one
 * (a TLS server that accepted an ML-KEM-1024 group, whatever group it named
 * first), else the algorithm label's, else, for a quantum-vulnerable
 * public-key finding without a label (a dependency), false.
 */
function cnsa2Of(finding: Finding, usage: readonly CryptoUsage[]): boolean | undefined {
  if (finding.cnsa2 !== undefined) return finding.cnsa2;
  const standing = cnsa2Standing(finding.algorithm);
  if (standing !== null) return standing;
  if (finding.pq_status === "vulnerable" && usage.some((u) => PUBLIC_KEY_USAGE.has(u))) return false;
  return undefined;
}

function withCnsa2(cnsa2: boolean | undefined): { cnsa2: boolean } | Record<string, never> {
  return cnsa2 === undefined ? {} : { cnsa2 };
}

/** An asset meets CNSA 2.0 only if every finding that says anything about it does. */
function combineCnsa2(current: boolean | undefined, next: boolean | undefined): boolean | undefined {
  if (current === false || next === false) return false;
  return current ?? next;
}

interface AssetDraft {
  asset: Omit<CryptoAsset, "verdict">;
  verdict: MoscaVerdict;
}

/** Assess a report against a profile: assets + Mosca verdicts + ledger + graph. */
export function assessRisk(target: string, findings: Finding[], profile: EstateProfile): RiskModel {
  assertProfileUsable(profile);
  const production = new Map<string, AssetDraft>();
  const nonProduction = new Map<string, AssetDraft>();
  for (const raw of findings) {
    const f = normalizeFinding(raw);
    const assessment = assessThreat(f);
    const v = worstVerdict(assessment, f.category, profile);
    const key = assetKey(f);
    // Documentation, tests, fixtures and examples are inventoried apart, so a
    // README table or a fixture key never stands in for the estate's exposure.
    const drafts = f.location?.context ? nonProduction : production;
    const existing = drafts.get(key);
    if (!existing) {
      drafts.set(key, {
        asset: {
          key,
          label: assetLabel(f, assessment.usage),
          category: f.category,
          ruleId: f.ruleId,
          usage: assessment.usage,
          pq_status: f.pq_status,
          ...withCnsa2(cnsa2Of(f, assessment.usage)),
          worstSeverity: f.severity,
          findingIds: [f.id],
        },
        verdict: v,
      });
      continue;
    }
    const a = existing.asset;
    a.findingIds.push(f.id);
    const cnsa2 = combineCnsa2(a.cnsa2, cnsa2Of(f, assessment.usage));
    if (cnsa2 !== undefined) a.cnsa2 = cnsa2;
    for (const u of assessment.usage) if (!a.usage.includes(u)) a.usage.push(u);
    if (PQ_RANK[f.pq_status] < PQ_RANK[a.pq_status]) a.pq_status = f.pq_status;
    if (SEVERITY_RANK[f.severity] < SEVERITY_RANK[a.worstSeverity]) a.worstSeverity = f.severity;
    if (STATUS_URGENCY[v.status] < STATUS_URGENCY[existing.verdict.status]) existing.verdict = v;
  }

  const toAssets = (drafts: Map<string, AssetDraft>): CryptoAsset[] =>
    [...drafts.values()].map(({ asset, verdict: v }) => ({ ...asset, verdict: v }));
  const assets = toAssets(production);
  const nonProductionAssets = toAssets(nonProduction);
  const ledger = buildLedger(assets, nonProductionAssets.length, profile.dataClass);
  const graph = buildGraph(target, assets, profile.dataClass);

  return {
    target,
    assumptions: {
      today: profile.today,
      crqcYear: profile.quantum.crqcYear,
      crqcBasis: profile.quantum.basis,
      dataClass: profile.dataClass.label,
      horizonYears: profile.dataClass.horizonYears,
      migrationYears: profile.migrationYears,
    },
    assets,
    nonProductionAssets,
    ledger,
    graph,
  };
}

/** The failure mode an asset's threat model represents, in obligation terms. */
const THREAT_SCOPE: Record<ThreatModel, ObligationScope | null> = {
  "harvest-now": "confidentiality",
  "forge-later": "identity",
  classical: "classical-strength",
  "not-applicable": null,
};

/** Statuses that mean an asset is not where its obligation requires it to be. */
const BREACHING_STATUSES: ReadonlySet<MoscaStatus> = new Set<MoscaStatus>(["exposed", "overdue", "act-now"]);

/**
 * Does this asset put the estate in breach of this obligation?
 *
 * Attribution is by failure mode: the ABA 1.6(c) safeguarding duty is breached by
 * a confidentiality exposure or by already-broken crypto, while the HNDL
 * obligation is breached only by the former. Counting every off-track asset
 * against every obligation produced one constant dressed as an attribution.
 * CNSA 2.0 is also breached by any public-key algorithm outside its parameter
 * sets, however far off the quantum deadline is.
 */
function breaches(asset: CryptoAsset, obligation: Obligation): boolean {
  if (obligation.scopes.includes("cnsa2-algorithms") && asset.cnsa2 === false) return true;
  if (!BREACHING_STATUSES.has(asset.verdict.status)) return false;
  const scope = THREAT_SCOPE[asset.verdict.threat];
  return scope !== null && obligation.scopes.includes(scope);
}

function buildLedger(assets: CryptoAsset[], nonProductionAssets: number, dataClass: DataClass): HarvestLedger {
  const exposed = assets.filter((a) => a.verdict.threat === "harvest-now" && a.verdict.status === "exposed");
  const overdue = assets.filter((a) => a.verdict.status === "overdue").length;
  const actNow = assets.filter((a) => a.verdict.status === "act-now").length;
  const onTrack = assets.filter((a) => a.verdict.status === "on-track").length;
  const exposureRiskYears = exposed.reduce((sum, a) => sum + a.verdict.horizonYears * dataClass.sensitivity, 0);

  const byObligation = dataClass.obligations.map((o) => ({
    obligation: o.label,
    assets: assets.filter((a) => breaches(a, o)).length,
  }));

  const verdictLine =
    exposed.length > 0
      ? `${exposed.length} asset(s) protecting ${dataClass.label.toLowerCase()} data are already exposed to harvest-now-decrypt-later (${exposureRiskYears.toFixed(0)} sensitivity-weighted risk-years accruing).`
      : overdue > 0
        ? `No harvest-now exposure at the current horizon, but ${overdue} asset(s) are on an overdue migration path.`
        : actNow > 0
          ? `No harvest-now-decrypt-later exposure at the current data horizon, but ${actNow} asset(s) are broken today without a quantum computer (act now).`
          : "No harvest-now-decrypt-later exposure at the current data horizon and quantum assumption.";
  const headline =
    nonProductionAssets > 0
      ? `${verdictLine} ${nonProductionAssets} asset(s) seen only in documentation, tests, fixtures or examples are listed separately and not counted.`
      : verdictLine;

  return {
    totalAssets: assets.length,
    nonProductionAssets,
    exposedAssets: exposed.length,
    overdueAssets: overdue,
    actNowAssets: actNow,
    onTrackAssets: onTrack,
    exposureRiskYears,
    headline,
    byObligation,
  };
}

function buildGraph(target: string, assets: CryptoAsset[], dataClass: DataClass): CryptoGraph {
  const systemId = "system:target";
  const dcId = `data-class:${dataClass.id}`;
  const nodes: GraphNode[] = [
    { id: systemId, type: "system", label: target },
    { id: dcId, type: "data-class", label: dataClass.label, props: { horizonYears: dataClass.horizonYears } },
  ];
  const edges: GraphEdge[] = [{ from: systemId, to: dcId, rel: "classified-as" }];

  for (const o of dataClass.obligations) {
    const oid = `obligation:${o.id}`;
    nodes.push({ id: oid, type: "obligation", label: o.label });
    edges.push({ from: dcId, to: oid, rel: "bound-by" });
  }
  for (const a of assets) {
    const aid = `asset:${a.key}`;
    nodes.push({
      id: aid,
      type: "asset",
      label: a.label,
      props: { pq_status: a.pq_status, threat: a.verdict.threat, status: a.verdict.status },
    });
    edges.push({ from: systemId, to: aid, rel: "uses" });
  }
  return { nodes, edges };
}

/** Re-export for consumers that want obligation types without importing estate. */
export type { Obligation, ObligationScope };
