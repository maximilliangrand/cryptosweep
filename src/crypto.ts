/**
 * Cryptographic-primitive knowledge base.
 *
 * A single, pure source of truth for "is this primitive broken by a
 * cryptographically-relevant quantum computer, and what does the standards
 * corpus say to do about it." Every scanner classifies through here so the
 * inventory speaks one vocabulary, and every classification carries a citation.
 */
import type { PqStatus, Reference, Severity } from "./report";

/** Canonical standards / advisory references, cited by findings. */
export const REFS = {
  fips203: { label: "NIST FIPS 203 (ML-KEM)", url: "https://csrc.nist.gov/pubs/fips/203/final" },
  fips204: { label: "NIST FIPS 204 (ML-DSA)", url: "https://csrc.nist.gov/pubs/fips/204/final" },
  fips205: { label: "NIST FIPS 205 (SLH-DSA)", url: "https://csrc.nist.gov/pubs/fips/205/final" },
  cnsa2: {
    label: "NSA CNSA 2.0 (2022)",
    url: "https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF",
  },
  ir8547: { label: "NIST IR 8547 (transition to PQC)", url: "https://csrc.nist.gov/pubs/ir/8547/ipd" },
  sp800131a: {
    label: "NIST SP 800-131A Rev.2 (SHA-1 disallowed for signatures)",
    url: "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final",
  },
  cwe327: {
    label: "CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)",
    url: "https://cwe.mitre.org/data/definitions/327.html",
  },
  hybridKex: {
    label: "draft-ietf-tls-hybrid-design (X25519MLKEM768)",
    url: "https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/",
  },
} as const satisfies Record<string, Reference>;

/** Public-key algorithm as reported by a Node `KeyObject`. */
export type KeyType = "rsa" | "rsa-pss" | "dsa" | "ec" | "ed25519" | "ed448" | "unknown";

/** OpenSSL curve names → the friendly names used across the security industry. */
const CURVE_NAMES: Readonly<Record<string, string>> = {
  prime256v1: "P-256",
  secp256r1: "P-256",
  secp384r1: "P-384",
  secp521r1: "P-521",
  secp256k1: "secp256k1",
};

export function curveFriendlyName(opensslName: string | null | undefined): string | null {
  if (!opensslName) return null;
  return CURVE_NAMES[opensslName] ?? opensslName;
}

/**
 * Is a public-key algorithm broken by Shor's algorithm?
 *
 * RSA and DSA fall to integer factorization / discrete log; EC (ECDSA/ECDH) and
 * EdDSA (Ed25519/Ed448) fall to the elliptic-curve discrete-log variant. All of
 * these are quantum-vulnerable. Only `unknown` is indeterminate.
 */
export function isQuantumVulnerableKey(keyType: KeyType): boolean {
  return keyType !== "unknown";
}

/** Approximate security strength (bits) of a named elliptic curve. */
function curveStrengthBits(curve: string | null): number | null {
  if (!curve) return null;
  const match = /(\d{3})/.exec(curve);
  return match?.[1] ? Number(match[1]) : null;
}

/**
 * Is a key classically broken *today*, independent of the quantum timeline?
 *
 * SP 800-131A Rev.2 disallows RSA/DSA below 2048 bits and ECC below a 224-bit
 * curve. This is a different question from "does Shor break it" — every key
 * below answers yes to both, and conflating the two is what made every
 * certificate on the internet look equally urgent.
 */
export function isClassicallyWeakKey(keyType: KeyType, bits: number | null, curve: string | null): boolean {
  if (keyType === "rsa" || keyType === "rsa-pss" || keyType === "dsa") return bits !== null && bits < 2048;
  if (keyType === "ec") {
    const strength = curveStrengthBits(curve);
    return strength !== null && strength < 224;
  }
  return false;
}

/**
 * Post-quantum posture and severity for a certificate/identity public key.
 *
 * Severity grades *classical* strength; `pq_status` carries the quantum verdict.
 * A sound RSA-4096 key and a factorable RSA-512 key are both `vulnerable` to a
 * CRQC, but only one of them is an emergency, and only that distinction makes a
 * `--fail-on high` CI gate mean anything.
 */
export function keyPosture(
  keyType: KeyType,
  bits: number | null = null,
  curve: string | null = null,
): {
  pq_status: PqStatus;
  severity: Severity;
  references: Reference[];
} {
  if (keyType === "unknown") {
    return { pq_status: "unknown", severity: "info", references: [] };
  }
  const references = [REFS.fips204, REFS.cnsa2, REFS.ir8547];
  if (isClassicallyWeakKey(keyType, bits, curve)) {
    const severity: Severity = bits !== null && bits < 1024 ? "critical" : "high";
    return { pq_status: "vulnerable", severity, references: [...references, REFS.sp800131a] };
  }
  return { pq_status: "vulnerable", severity: "medium", references };
}

/** A canonical, inventory-friendly label for a public key, e.g. "RSA-2048", "ECDSA-P-256". */
export function keyAlgorithmLabel(keyType: KeyType, bits: number | null, curve: string | null): string {
  switch (keyType) {
    case "rsa":
      return `RSA-${bits ?? "?"}`;
    case "rsa-pss":
      return `RSA-PSS-${bits ?? "?"}`;
    case "dsa":
      return `DSA-${bits ?? "?"}`;
    case "ec":
      return `ECDSA-${curve ?? "unknown-curve"}`;
    case "ed25519":
      return "Ed25519";
    case "ed448":
      return "Ed448";
    default:
      return "unknown-key";
  }
}
