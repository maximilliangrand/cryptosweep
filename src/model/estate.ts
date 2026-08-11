/**
 * Estate profile: the organizational context the risk engine reasons over.
 *
 * A scan finds *what crypto exists*. Risk needs three things a scan cannot infer
 * from code: how long the protected data must stay secret (the confidentiality
 * horizon), when a cryptographically-relevant quantum computer is assumed to
 * arrive, and how long migration takes. Those are business inputs, so they live
 * here, with honest defaults and full overridability. The whole model is a pure
 * function of (findings, profile), so it is reproducible and defensible.
 */
import { REFS } from "../crypto";
import type { Reference } from "../report";

/**
 * What kind of cryptographic failure an obligation actually binds.
 *
 * This is the ontology edge that makes per-obligation attribution real rather
 * than decorative: without it every obligation reports the same total, which
 * looks derived and is not.
 *
 * - `confidentiality`, data recorded today and decrypted later (harvest-now).
 * - `identity`, signatures and identity keys forgeable once a CRQC exists.
 * - `classical-strength`, primitives already broken without a quantum computer.
 */
export type ObligationScope = "confidentiality" | "identity" | "classical-strength";

export interface Obligation {
  id: string;
  label: string;
  /** The failure modes this obligation is breached by. */
  scopes: ObligationScope[];
  reference?: Reference;
}

export interface DataClass {
  id: string;
  label: string;
  /** Confidentiality horizon: years the data must remain secret (Mosca's X). */
  horizonYears: number;
  /** 0..1 sensitivity weight used by the harvest-exposure ledger. */
  sensitivity: number;
  /** Regulatory / duty obligations that bind this data class. */
  obligations: Obligation[];
}

export interface QuantumAssumption {
  /** Year a cryptographically-relevant quantum computer is assumed to exist (Mosca's Z). */
  crqcYear: number;
  /** Where the assumption comes from — surfaced so nobody mistakes it for a fact. */
  basis: string;
}

export interface EstateProfile {
  /** ISO date the model is computed as-of. */
  today: string;
  quantum: QuantumAssumption;
  /** Migration time (years, Mosca's Y) by finding category, with a fallback. */
  migrationYears: { byCategory: Partial<Record<string, number>>; default: number };
  /** The data class applied to the scanned estate. */
  dataClass: DataClass;
  /** Selectable data-class catalog. */
  catalog: DataClass[];
}

const OBLIGATIONS = {
  // Purely a confidentiality exposure: signatures are not harvested.
  hndl: { id: "hndl", label: "Harvest-now-decrypt-later exposure", scopes: ["confidentiality"], reference: REFS.ir8547 },
  // CNSA 2.0 mandates PQ key establishment AND PQ signatures.
  cnsa2: { id: "cnsa-2.0", label: "NSA CNSA 2.0 federal PQC mandate", scopes: ["confidentiality", "identity"], reference: REFS.cnsa2 },
  // A competence duty is breached by shipping already-broken crypto too.
  aba16c: {
    id: "aba-1.6c",
    label: "ABA Model Rule 1.6(c) duty of technological competence",
    scopes: ["confidentiality", "classical-strength"],
  },
  hipaa: {
    id: "hipaa",
    label: "HIPAA Security Rule (multi-decade PHI retention)",
    scopes: ["confidentiality", "classical-strength"],
  },
} as const satisfies Record<string, Obligation>;

const GENERAL: DataClass = {
  id: "general",
  label: "General business",
  horizonYears: 7,
  sensitivity: 0.5,
  obligations: [OBLIGATIONS.hndl],
};

/** Named data classes, ordered longest-horizon first. Horizons are typical, not legal advice. */
export const DATA_CLASSES: readonly DataClass[] = [
  { id: "legal-privileged", label: "Legal / privileged", horizonYears: 30, sensitivity: 1.0, obligations: [OBLIGATIONS.aba16c, OBLIGATIONS.hndl] },
  { id: "medical-phi", label: "Medical / PHI", horizonYears: 25, sensitivity: 0.95, obligations: [OBLIGATIONS.hipaa, OBLIGATIONS.hndl] },
  { id: "government-cui", label: "Government / CUI", horizonYears: 25, sensitivity: 1.0, obligations: [OBLIGATIONS.cnsa2, OBLIGATIONS.hndl] },
  { id: "financial-pii", label: "Financial / PII", horizonYears: 10, sensitivity: 0.8, obligations: [OBLIGATIONS.hndl] },
  { id: "secrets", label: "Secrets / credentials", horizonYears: 5, sensitivity: 0.9, obligations: [OBLIGATIONS.hndl] },
  GENERAL,
  { id: "public", label: "Public", horizonYears: 0, sensitivity: 0.0, obligations: [] },
];

const DEFAULT_CRQC_YEAR = 2035;

/** True if `id` names a known data class. */
export function isDataClassId(id: string | undefined): boolean {
  return DATA_CLASSES.some((c) => c.id === id);
}

/** Build a default profile, optionally selecting a data class and CRQC year. */
export function defaultProfile(today: string, opts: { dataClassId?: string; crqcYear?: number } = {}): EstateProfile {
  const dataClass = DATA_CLASSES.find((c) => c.id === opts.dataClassId) ?? GENERAL;
  return {
    today,
    quantum: {
      crqcYear: opts.crqcYear ?? DEFAULT_CRQC_YEAR,
      basis:
        "Assumption, not a forecast. Default aligns with common expert-survey medians for a cryptographically-relevant quantum computer; override with --crqc-year.",
    },
    migrationYears: {
      byCategory: { tls: 1, deps: 0.5, source: 0.5, keys: 0.25, jwt: 0.5 },
      default: 1,
    },
    dataClass,
    catalog: [...DATA_CLASSES],
  };
}
