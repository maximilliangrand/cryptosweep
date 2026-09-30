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
  fips1865: {
    label: "NIST FIPS 186-5 (DSA no longer approved for signature generation)",
    url: "https://csrc.nist.gov/pubs/fips/186-5/final",
  },
  cnsa2: {
    label: "NSA CNSA 2.0 (2022)",
    url: "https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF",
  },
  ir8547: {
    label: "NIST IR 8547 initial public draft (transition to PQC standards)",
    url: "https://csrc.nist.gov/pubs/ir/8547/ipd",
  },
  sp800131a: {
    label: "NIST SP 800-131A Rev.2 (transitioning cryptographic algorithms and key lengths)",
    url: "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final",
  },
  cwe327: {
    label: "CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)",
    url: "https://cwe.mitre.org/data/definitions/327.html",
  },
  // The document that specifies the X25519MLKEM768 codepoint (and the NIST-curve
  // hybrids), published from draft-ietf-tls-ecdhe-mlkem. RFC 9954 (formerly
  // draft-ietf-tls-hybrid-design) is only the generic construction.
  hybridKex: {
    label: "RFC 10024 (PQ/T hybrid key agreement for TLS 1.3: X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024)",
    url: "https://www.rfc-editor.org/rfc/rfc10024",
  },
  hybridDesign: {
    label: "RFC 9954 (hybrid key exchange in TLS 1.3)",
    url: "https://www.rfc-editor.org/rfc/rfc9954",
  },
  // Still an Internet-Draft; no RFC number has been assigned.
  mlkemKex: {
    label: "draft-ietf-tls-mlkem (pure ML-KEM groups MLKEM768, MLKEM1024 for TLS 1.3)",
    url: "https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/",
  },
} as const satisfies Record<string, Reference>;

/**
 * Public-key types Shor's algorithm breaks, named as a Node `KeyObject`
 * reports them. RSA and DSA fall to integer factorization / discrete log; EC
 * (ECDSA/ECDH) and EdDSA (Ed25519/Ed448) fall to the elliptic-curve variant.
 */
const QUANTUM_VULNERABLE_KEY_TYPES = ["rsa", "rsa-pss", "dsa", "ec", "ed25519", "ed448"] as const;

/** NIST post-quantum public-key types: FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA). */
const POST_QUANTUM_KEY_TYPES = [
  "ml-kem-512",
  "ml-kem-768",
  "ml-kem-1024",
  "ml-dsa-44",
  "ml-dsa-65",
  "ml-dsa-87",
  "slh-dsa-sha2-128s",
  "slh-dsa-sha2-128f",
  "slh-dsa-sha2-192s",
  "slh-dsa-sha2-192f",
  "slh-dsa-sha2-256s",
  "slh-dsa-sha2-256f",
  "slh-dsa-shake-128s",
  "slh-dsa-shake-128f",
  "slh-dsa-shake-192s",
  "slh-dsa-shake-192f",
  "slh-dsa-shake-256s",
  "slh-dsa-shake-256f",
] as const;

export type QuantumVulnerableKeyType = (typeof QUANTUM_VULNERABLE_KEY_TYPES)[number];
export type PostQuantumKeyType = (typeof POST_QUANTUM_KEY_TYPES)[number];

/**
 * Public-key algorithm as reported by a Node `KeyObject`. The union is built
 * from the two classification tables above, so a type cannot be added without
 * also being classified.
 */
export type KeyType = QuantumVulnerableKeyType | PostQuantumKeyType | "unknown";

const QUANTUM_VULNERABLE: ReadonlySet<string> = new Set(QUANTUM_VULNERABLE_KEY_TYPES);
const POST_QUANTUM: ReadonlySet<string> = new Set(POST_QUANTUM_KEY_TYPES);

/** Narrow a `KeyObject.asymmetricKeyType` string to a classified key type, or "unknown". */
export function toKeyType(reported: string | null | undefined): KeyType {
  return reported && isKeyType(reported) ? reported : "unknown";
}

function isKeyType(value: string): value is KeyType {
  return QUANTUM_VULNERABLE.has(value) || POST_QUANTUM.has(value);
}

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
 * An explicit allow list of the classical types. Anything else, a post-quantum
 * key or a type this table has never seen, is not called vulnerable: a
 * correctly migrated key must never be reported as the thing it replaced.
 */
export function isQuantumVulnerableKey(keyType: KeyType): boolean {
  return QUANTUM_VULNERABLE.has(keyType);
}

/** Is a public-key algorithm one of the NIST post-quantum standards? */
export function isPostQuantumKey(keyType: KeyType): keyType is PostQuantumKeyType {
  return POST_QUANTUM.has(keyType);
}

/**
 * Does a post-quantum key use the CNSA 2.0 parameter set? CNSA 2.0 specifies
 * ML-KEM-1024 and ML-DSA-87 only; SLH-DSA is not part of the suite.
 */
export function meetsCnsa2(keyType: KeyType): boolean {
  return keyType === "ml-kem-1024" || keyType === "ml-dsa-87";
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
 * NIST IR 8547 (initial public draft) transition dates for a quantum-vulnerable
 * key that is classically sound. Keys at the 112-bit security strength (RSA
 * below 3072 bits, ECC below a 256-bit curve) are deprecated after 2030; every
 * quantum-vulnerable key is disallowed after 2035. Returns null for keys the
 * schedule does not cover (post-quantum, unknown, or already below the floor).
 */
export function ir8547Transition(
  keyType: KeyType,
  bits: number | null,
  curve: string | null,
): { deprecatedAfter: number | null; disallowedAfter: number } | null {
  if (!isQuantumVulnerableKey(keyType) || isClassicallyWeakKey(keyType, bits, curve)) return null;
  let strength112 = false;
  if (keyType === "rsa" || keyType === "rsa-pss" || keyType === "dsa") strength112 = bits !== null && bits < 3072;
  if (keyType === "ec") strength112 = (curveStrengthBits(curve) ?? 256) < 256;
  return { deprecatedAfter: strength112 ? 2030 : null, disallowedAfter: 2035 };
}

/** The FIPS standard that defines a post-quantum key type. */
function postQuantumReference(keyType: PostQuantumKeyType): Reference {
  if (keyType.startsWith("ml-kem")) return REFS.fips203;
  if (keyType.startsWith("ml-dsa")) return REFS.fips204;
  return REFS.fips205;
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
  if (isPostQuantumKey(keyType)) {
    return { pq_status: "safe", severity: "info", references: [postQuantumReference(keyType), REFS.cnsa2] };
  }
  if (!isQuantumVulnerableKey(keyType)) {
    return { pq_status: "unknown", severity: "info", references: [] };
  }
  const references: Reference[] = [REFS.fips204, REFS.cnsa2, REFS.ir8547];
  if (keyType === "dsa") references.push(REFS.fips1865);
  if (isClassicallyWeakKey(keyType, bits, curve)) {
    const severity: Severity = bits !== null && bits < 1024 ? "critical" : "high";
    return { pq_status: "vulnerable", severity, references: [...references, REFS.sp800131a] };
  }
  return { pq_status: "vulnerable", severity: "medium", references };
}

/** SLH-DSA key types keep their lowercase s/f variant suffix, as FIPS 205 writes them. */
function slhDsaLabel(keyType: string): string | null {
  const match = /^slh-dsa-(sha2|shake)-(\d+)([sf])$/.exec(keyType);
  return match ? `SLH-DSA-${(match[1] ?? "").toUpperCase()}-${match[2] ?? ""}${match[3] ?? ""}` : null;
}

/**
 * A canonical, inventory-friendly label for a public key, e.g. "RSA-2048",
 * "ECDSA-P-256", "ML-DSA-65", "SLH-DSA-SHA2-128s".
 */
export function keyAlgorithmLabel(keyType: KeyType, bits: number | null, curve: string | null): string {
  if (isPostQuantumKey(keyType)) return slhDsaLabel(keyType) ?? keyType.toUpperCase();
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
