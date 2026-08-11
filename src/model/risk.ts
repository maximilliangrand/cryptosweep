/**
 * Crypto-agility risk engine.
 *
 * Projects a scan Report + an EstateProfile into three things a scanner cannot:
 *   1. a Mosca-clock verdict per cryptographic asset (is it already too late?),
 *   2. a harvest-exposure ledger (the growing confidentiality liability), and
 *   3. an ontology graph linking assets -> system -> data class -> obligations.
 *
 * The threat model is not one-size-fits-all, on purpose:
 *   - harvest-now: confidentiality crypto (key exchange). An adversary recording
 *     today decrypts once a CRQC exists, so the deadline is pulled *backward* by
 *     the data's secrecy horizon. This is the only thing in the harvest ledger.
 *   - forge-later: signatures / identity keys. No retroactive harvest; the
 *     deadline is simply "migrate before the CRQC".
 *   - classical: MD5 / SHA-1 / DES. Broken today, independent of quantum; on the
 *     board as "fix now", but never on the quantum clock and never in the ledger.
 */
import type { Finding, PqStatus, Severity } from "../report";
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
  pq_status: PqStatus;
  worstSeverity: Severity;
  findingIds: string[];
  verdict: MoscaVerdict;
}

export interface HarvestLedger {
  totalAssets: number;
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
  };
  assets: CryptoAsset[];
  ledger: HarvestLedger;
  graph: CryptoGraph;
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const CLASSICAL = /\bmd5\b|sha-?1|(?:^|[^a-z])(?:des|rc4|rc2)(?:[^a-z]|$)/i;
const KEY_EXCHANGE = /mlkem|kyber|x25519|x448|ecdh|\bdh\b|\bkem\b|key.?exchange|hybrid/i;
/** Dependencies whose primary job is key exchange / TLS transport -> harvest-now. */
const HARVEST_DEPS = new Set(["rustls", "ring", "openssl", "x25519-dalek", "pyopenssl", "paramiko", "node-forge"]);

/**
 * Key labels below the SP 800-131A classical minimum (RSA/DSA < 2048 bits,
 * ECC < 224-bit curve). These are broken without a quantum computer, so they
 * belong on the act-now board, not on the Mosca clock.
 */
function isClassicallyWeakLabel(algorithm: string | undefined): boolean {
  if (!algorithm) return false;
  const integer = /^(?:rsa|rsa-pss|dsa)-(\d+)$/i.exec(algorithm);
  if (integer?.[1]) return Number(integer[1]) < 2048;
  const elliptic = /^ecdsa-(?:p-|secp|sect|brainpoolp)?(\d+)/i.exec(algorithm);
  if (elliptic?.[1]) return Number(elliptic[1]) < 224;
  return false;
}

/** Classify a cryptographic asset into its actual threat model. */
export function classifyThreat(finding: Finding): ThreatModel {
  if (finding.pq_status !== "vulnerable") return "not-applicable";
  const label = `${finding.algorithm ?? ""} ${finding.ruleId ?? ""} ${finding.title}`.toLowerCase();
  if (CLASSICAL.test(finding.algorithm ?? label)) return "classical";
  if (isClassicallyWeakLabel(finding.algorithm)) return "classical";
  if (finding.category === "tls" && /hybrid-kex/.test(finding.ruleId ?? "")) return "harvest-now";
  if (finding.category === "deps") {
    const name = (finding.ruleId ?? "").replace(/^deps\/[a-z]+-/, "");
    if (HARVEST_DEPS.has(name)) return "harvest-now";
    return "forge-later";
  }
  if (KEY_EXCHANGE.test(label)) return "harvest-now";
  return "forge-later";
}

function fractionalYear(iso: string): number {
  const date = new Date(iso);
  const year = date.getUTCFullYear();
  const start = Date.UTC(year, 0, 1);
  const nextYear = Date.UTC(year + 1, 0, 1);
  return year + (date.getTime() - start) / (nextYear - start);
}

function verdict(threat: ThreatModel, category: string, profile: EstateProfile): MoscaVerdict {
  const today = fractionalYear(profile.today);
  const crqcYear = profile.quantum.crqcYear;
  const yearsToCrqc = crqcYear - today;
  const migrationYears = profile.migrationYears.byCategory[category] ?? profile.migrationYears.default;
  const horizonYears = profile.dataClass.horizonYears;
  const base = { threat, migrationYears, crqcYear, yearsToCrqc, horizonYears };

  if (threat === "not-applicable") {
    return { ...base, status: "not-applicable", mustCompleteInYears: NaN, mustStartInYears: NaN, rationale: "Not quantum-vulnerable." };
  }
  if (threat === "classical") {
    return {
      ...base,
      status: "act-now",
      mustCompleteInYears: 0,
      mustStartInYears: 0,
      rationale: "Classically broken today (collision / cipher weakness); remediate now, independent of the quantum timeline.",
    };
  }
  if (threat === "harvest-now") {
    if (horizonYears <= 0) {
      return { ...base, status: "not-applicable", mustCompleteInYears: NaN, mustStartInYears: NaN, rationale: "Public data has no confidentiality horizon to protect." };
    }
    const mustCompleteInYears = yearsToCrqc - horizonYears;
    const mustStartInYears = mustCompleteInYears - migrationYears;
    if (mustCompleteInYears < 0) {
      return {
        ...base,
        status: "exposed",
        mustCompleteInYears,
        mustStartInYears,
        rationale: `Data with a ${horizonYears}-year secrecy horizon recorded today is still sensitive when a CRQC (~${crqcYear}) can decrypt it. Harvest-now-decrypt-later exposure is already accruing.`,
      };
    }
    const status: MoscaStatus = mustStartInYears < 0 ? "overdue" : "on-track";
    return { ...base, status, mustCompleteInYears, mustStartInYears, rationale: moscaRationale(status, mustStartInYears, mustCompleteInYears) };
  }
  // forge-later: no harvest window; must simply migrate before the CRQC.
  const mustCompleteInYears = yearsToCrqc;
  const mustStartInYears = yearsToCrqc - migrationYears;
  const status: MoscaStatus = yearsToCrqc <= 0 ? "exposed" : mustStartInYears < 0 ? "overdue" : "on-track";
  return {
    ...base,
    status,
    mustCompleteInYears,
    mustStartInYears,
    rationale:
      status === "on-track"
        ? `Signature/identity crypto: forgeable once a CRQC exists (~${crqcYear}). Begin migration within ${mustStartInYears.toFixed(1)} year(s).`
        : "Signature/identity crypto: migration must already be underway to rotate before a CRQC enables forgery.",
  };
}

function moscaRationale(status: MoscaStatus, start: number, complete: number): string {
  if (status === "overdue") return `Migration is overdue: it needed to start ${Math.abs(start).toFixed(1)} year(s) ago to complete before harvested data becomes decryptable.`;
  return `On track: begin within ${start.toFixed(1)} year(s) and complete within ${complete.toFixed(1)} to stay ahead of harvest-now-decrypt-later.`;
}

/** Group findings into distinct cryptographic assets keyed by algorithm/library/kind. */
function assetKey(f: Finding): { key: string; label: string } {
  if (f.algorithm) return { key: f.algorithm, label: f.algorithm };
  if (f.category === "deps") {
    const name = (f.ruleId ?? "").replace(/^deps\//, "") || f.title;
    return { key: `dep:${name}`, label: name };
  }
  if (f.category === "keys") return { key: "hardcoded-private-key", label: "Hardcoded private key" };
  return { key: f.ruleId ?? f.title, label: f.title };
}

const PQ_RANK: Record<PqStatus, number> = { vulnerable: 0, transitional: 1, unknown: 2, safe: 3 };

/** Assess a report against a profile: assets + Mosca verdicts + ledger + graph. */
export function assessRisk(target: string, findings: Finding[], profile: EstateProfile): RiskModel {
  const byKey = new Map<string, { label: string; category: string; pq: PqStatus; sev: Severity; ids: string[] }>();
  for (const f of findings) {
    const { key, label } = assetKey(f);
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, { label, category: f.category, pq: f.pq_status, sev: f.severity, ids: [f.id] });
    } else {
      existing.ids.push(f.id);
      if (PQ_RANK[f.pq_status] < PQ_RANK[existing.pq]) existing.pq = f.pq_status;
      if (SEVERITY_RANK[f.severity] < SEVERITY_RANK[existing.sev]) existing.sev = f.severity;
    }
  }

  const assets: CryptoAsset[] = [...byKey.entries()].map(([key, a]) => {
    const representative: Finding = {
      id: a.ids[0] ?? key,
      severity: a.sev,
      category: a.category as Finding["category"],
      title: a.label,
      evidence: "",
      pq_status: a.pq,
      recommendation: "",
      algorithm: a.label,
      ruleId: key.startsWith("dep:") ? `deps/${key.slice(4)}` : undefined,
    };
    const threat = classifyThreat(representative);
    return {
      key,
      label: a.label,
      category: a.category,
      pq_status: a.pq,
      worstSeverity: a.sev,
      findingIds: a.ids,
      verdict: verdict(threat, a.category, profile),
    };
  });

  const ledger = buildLedger(assets, profile.dataClass);
  const graph = buildGraph(target, assets, profile.dataClass);

  return {
    target,
    assumptions: {
      today: profile.today,
      crqcYear: profile.quantum.crqcYear,
      crqcBasis: profile.quantum.basis,
      dataClass: profile.dataClass.label,
      horizonYears: profile.dataClass.horizonYears,
    },
    assets,
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
 * Attribution is by failure mode: an ABA 1.6(c) competence duty is breached by
 * a confidentiality exposure or by already-broken crypto, while the HNDL
 * obligation is breached only by the former. Counting every off-track asset
 * against every obligation produced one constant dressed as an attribution.
 */
function breaches(asset: CryptoAsset, obligation: Obligation): boolean {
  if (!BREACHING_STATUSES.has(asset.verdict.status)) return false;
  const scope = THREAT_SCOPE[asset.verdict.threat];
  return scope !== null && obligation.scopes.includes(scope);
}

function buildLedger(assets: CryptoAsset[], dataClass: DataClass): HarvestLedger {
  const exposed = assets.filter((a) => a.verdict.threat === "harvest-now" && a.verdict.status === "exposed");
  const overdue = assets.filter((a) => a.verdict.status === "overdue").length;
  const actNow = assets.filter((a) => a.verdict.status === "act-now").length;
  const onTrack = assets.filter((a) => a.verdict.status === "on-track").length;
  const exposureRiskYears = exposed.reduce((sum, a) => sum + a.verdict.horizonYears * dataClass.sensitivity, 0);

  const byObligation = dataClass.obligations.map((o) => ({
    obligation: o.label,
    assets: assets.filter((a) => breaches(a, o)).length,
  }));

  const headline =
    exposed.length > 0
      ? `${exposed.length} asset(s) protecting ${dataClass.label.toLowerCase()} data are already exposed to harvest-now-decrypt-later (${exposureRiskYears.toFixed(0)} sensitivity-weighted risk-years accruing).`
      : overdue > 0
        ? `No harvest-now exposure at the current horizon, but ${overdue} asset(s) are on an overdue migration path.`
        : "No harvest-now-decrypt-later exposure at the current data horizon and quantum assumption.";

  return {
    totalAssets: assets.length,
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
