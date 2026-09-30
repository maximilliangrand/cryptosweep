/**
 * Estate profile: the organizational context the risk engine reasons over.
 *
 * A scan finds *what crypto exists*. Risk needs three things a scan cannot infer
 * from code: how long the protected data must stay secret (the confidentiality
 * horizon), when a cryptographically-relevant quantum computer is assumed to
 * arrive, and how long migration takes. Those are business inputs, so they live
 * here, with cited defaults that {@link defaultProfile} lets a caller override.
 * The whole model is a pure function of (findings, profile), so it is
 * reproducible and defensible.
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

/** Mosca's Y: how long migrating an asset takes, in years. */
export interface MigrationAssumption {
  /** Per finding category; wins over `byThreat` when set. */
  byCategory: Partial<Record<string, number>>;
  /** Per threat model: key establishment and signatures migrate on different clocks. */
  byThreat?: Partial<Record<"harvest-now" | "forge-later", number>>;
  default: number;
  /** Where the numbers come from, surfaced next to every verdict. */
  basis?: string;
}

export interface EstateProfile {
  /** ISO date the model is computed as-of. */
  today: string;
  quantum: QuantumAssumption;
  /** Migration time (years, Mosca's Y). */
  migrationYears: MigrationAssumption;
  /** The data class applied to the scanned estate. */
  dataClass: DataClass;
  /** Selectable data-class catalog. */
  catalog: DataClass[];
}

const OBLIGATIONS = {
  // Purely a confidentiality exposure: signatures are not harvested.
  hndl: { id: "hndl", label: "Harvest-now-decrypt-later exposure", scopes: ["confidentiality"], reference: REFS.ir8547 },
  // CNSA 2.0 mandates PQ key establishment AND PQ signatures, but only for
  // National Security Systems; most CUI systems are bound by NIST guidance instead.
  cnsa2: {
    id: "cnsa-2.0",
    label: "NSA CNSA 2.0 (binding on National Security Systems)",
    scopes: ["confidentiality", "identity"],
    reference: REFS.cnsa2,
  },
  // Rule 1.6(c) requires reasonable efforts to prevent unauthorized disclosure
  // of client information; shipping already-broken crypto falls short of it too.
  // (The technology-competence duty is Rule 1.1, Comment 8.)
  aba16c: {
    id: "aba-1.6c",
    label: "ABA Model Rule 1.6(c) reasonable efforts to safeguard client information",
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

/**
 * Default CRQC year (Mosca's Z). An assumption, not a forecast: 2035 is the
 * date the published migration programmes plan against (see {@link CRQC_BASIS}),
 * so verdicts line up with the deadlines an estate is already held to.
 */
const DEFAULT_CRQC_YEAR = 2035;

const CRQC_BASIS =
  "Assumption, not a forecast. 2035 is the planning date shared by US NSM-10 (federal goal to mitigate quantum risk by 2035), " +
  "NIST IR 8547 (quantum-vulnerable algorithms disallowed after 2035) and the UK NCSC migration timeline (migration complete by 2035); " +
  "nobody knows when a cryptographically-relevant quantum computer will exist. Override with --crqc-year.";

/**
 * Default migration times (Mosca's Y), in years for a whole estate, from
 * inventory through rollout, not just the code change. Planning assumptions,
 * chosen against published programmes rather than optimistically:
 *
 * - UK NCSC, "Timelines for migration to post-quantum cryptography" (2025):
 *   discovery and planning by 2028, highest-priority migrations by 2031, i.e.
 *   about three years of execution for the systems that matter most.
 * - Key establishment (harvest-now) is on that three-year clock: hybrid
 *   ML-KEM groups already ship in mainstream TLS/SSH stacks, so the time goes
 *   into rollout and interop testing, not waiting for standards.
 * - Signatures and identity (forge-later) take five: PQ certificates need CA,
 *   HSM and relying-party support that the public web PKI does not have yet.
 *   The last comparable swap, SHA-1 to SHA-256 certificates, took about six
 *   years from NIST's 2011 transition guidance (SP 800-131A) to browser
 *   distrust in 2017, with CA support already in place.
 * - NIST IR 8105 (2016) records that deploying today's public-key
 *   infrastructure took "almost two decades"; five years is not conservative
 *   for an estate that has not started.
 */
export const DEFAULT_MIGRATION_YEARS: Readonly<MigrationAssumption> = {
  byCategory: {},
  byThreat: { "harvest-now": 3, "forge-later": 5 },
  default: 5,
  basis:
    "Assumption: 3 years for key establishment (UK NCSC 2025 timeline: highest-priority migrations 2028-2031, hybrid ML-KEM already shipping), " +
    "5 years for signatures/PKI (PQ certificates need CA and relying-party support; the SHA-1 certificate sunset took ~6 years). Override per estate.",
};

/** True if `id` names a known data class. */
export function isDataClassId(id: string | undefined): boolean {
  return DATA_CLASSES.some((c) => c.id === id);
}

export interface ProfileOptions {
  dataClassId?: string;
  /** Assumed CRQC year (Mosca's Z). */
  crqcYear?: number;
  /** Uniform migration time in years (Mosca's Y), replacing every default. */
  migrationYears?: number;
}

/** Latest and earliest CRQC years accepted: outside them the arithmetic is still defined but the input is a typo. */
const CRQC_YEAR_RANGE = { min: 1990, max: 2200 } as const;
const MAX_MIGRATION_YEARS = 100;

/**
 * Build a default profile, optionally selecting a data class, CRQC year and
 * migration time. Throws a RangeError for inputs the Mosca arithmetic cannot
 * use: a NaN or absurd year used to fall through every comparison and come
 * out as "on-track".
 */
export function defaultProfile(today: string, opts: ProfileOptions = {}): EstateProfile {
  const dataClass = DATA_CLASSES.find((c) => c.id === opts.dataClassId) ?? GENERAL;
  const crqcYear = opts.crqcYear ?? DEFAULT_CRQC_YEAR;
  const migrationYears: MigrationAssumption =
    opts.migrationYears === undefined
      ? { ...DEFAULT_MIGRATION_YEARS, byCategory: {}, byThreat: { ...DEFAULT_MIGRATION_YEARS.byThreat } }
      : { byCategory: {}, default: opts.migrationYears, basis: "Caller-supplied migration time, applied to every asset." };
  const profile: EstateProfile = {
    today,
    quantum: { crqcYear, basis: CRQC_BASIS },
    migrationYears,
    dataClass,
    catalog: [...DATA_CLASSES],
  };
  assertProfileUsable(profile);
  return profile;
}

/**
 * Reject a profile whose numbers would make a Mosca verdict meaningless.
 * Exported so the risk engine can apply it to hand-built profiles too.
 */
export function assertProfileUsable(profile: EstateProfile): void {
  if (Number.isNaN(new Date(profile.today).getTime())) {
    throw new RangeError(`profile date is not a valid ISO date: ${profile.today}`);
  }
  const { crqcYear } = profile.quantum;
  if (!Number.isFinite(crqcYear) || crqcYear < CRQC_YEAR_RANGE.min || crqcYear > CRQC_YEAR_RANGE.max) {
    throw new RangeError(`CRQC year must be a year between ${CRQC_YEAR_RANGE.min} and ${CRQC_YEAR_RANGE.max} (got ${crqcYear})`);
  }
  const { byCategory, byThreat, default: fallback } = profile.migrationYears;
  const years = [fallback, ...Object.values(byCategory), ...Object.values(byThreat ?? {})];
  for (const value of years) {
    if (value === undefined) continue;
    if (!Number.isFinite(value) || value <= 0 || value > MAX_MIGRATION_YEARS) {
      throw new RangeError(`migration time must be a number of years in (0, ${MAX_MIGRATION_YEARS}] (got ${value})`);
    }
  }
  const { horizonYears, sensitivity } = profile.dataClass;
  if (!Number.isFinite(horizonYears) || horizonYears < 0) {
    throw new RangeError(`data-class horizon must be a non-negative number of years (got ${horizonYears})`);
  }
  if (!Number.isFinite(sensitivity) || sensitivity < 0 || sensitivity > 1) {
    throw new RangeError(`data-class sensitivity must be in [0, 1] (got ${sensitivity})`);
  }
}
