/**
 * Dependency-audit registry.
 *
 * Pure-data module: each entry describes a single (name, ecosystem) pair that
 * we want to flag, along with the PQ posture, the migration recommendation, and
 * at least one provenance reference explaining why it is flagged. No I/O.
 *
 * Inclusion rule: add a (name, ecosystem) only for a library that either ships
 * or wraps a classical asymmetric primitive at risk from Shor (RSA / DSA /
 * ECDSA / ECDH / Ed25519 / X25519 / secp256k1), or is a post-quantum library
 * (mark it transitional). Every vulnerable/transitional entry carries >= 1
 * reference. Set `fixedIn` ONLY when a specific released version added a
 * PQ-relevant capability that flips the assessment; libraries classical by
 * nature at every version omit it and are flagged regardless of version.
 *
 * Sources used while seeding:
 *   - NIST PQC standards (FIPS 203/204/205) and IR 8547 (migration).
 *   - CNSA 2.0 (NSA, 2022), RSA/ECDSA deprecation timeline.
 *   - Package maintainers' own README/changelogs.
 */
import { REFS } from "../../crypto";
import type { PqStatus, Reference, Severity } from "../../report";

export type Ecosystem = "npm" | "python" | "cargo";

export interface RegistryEntry {
  name: string;
  ecosystem: Ecosystem;
  /** Semver / PEP440 / cargo range. Defaults to "*", see file header. */
  version_range?: string;
  /**
   * The first version at which the library's post-quantum-relevant concern is
   * addressed (e.g. a hybrid KEM group became available). When set, the scanner
   * only flags installs whose permitted floor is BELOW this version; at or above
   * it, the finding is downgraded to transitional. Omit for libraries that are
   * classical by nature at every version (RSA/ECDSA implementations), which are
   * correctly flagged regardless of version.
   */
  fixedIn?: string;
  severity: Severity;
  pq_status: PqStatus;
  reason: string;
  recommendation: string;
  /** Provenance: standards / advisories backing this entry's classification. */
  references?: Reference[];
}

export const REGISTRY: readonly RegistryEntry[] = [
  // ---------- npm ----------
  {
    name: "jsonwebtoken",
    ecosystem: "npm",
    severity: "high",
    pq_status: "vulnerable",
    reason:
      "Widely used JWT library; defaults invite HS256 (symmetric, key-leak prone) and the RS256/ES256 paths rely on classical RSA/ECDSA broken by Shor's algorithm.",
    recommendation:
      "Prefer `jose` with EdDSA or RSA-PSS keys; plan a PQ-signature pilot (e.g. ML-DSA via a hybrid JWS).",
    references: [REFS.fips204],
  },
  {
    name: "node-rsa",
    ecosystem: "npm",
    severity: "high",
    pq_status: "vulnerable",
    reason: "Pure-JS RSA implementation; RSA key exchange/signatures are broken by CRQCs.",
    recommendation:
      "Migrate to native `node:crypto` and plan hybrid (X25519+ML-KEM) key exchange or ML-DSA signatures.",
    references: [REFS.fips204, REFS.fips203],
  },
  {
    name: "node-forge",
    ecosystem: "npm",
    severity: "medium",
    pq_status: "vulnerable",
    reason:
      "Legacy crypto toolkit (X.509, PKCS, RSA, AES) commonly used in browsers/Electron; ships only classical primitives.",
    recommendation:
      "Move primitives to native `node:crypto` (or WebCrypto) and design a hybrid KEM/signature plan.",
    references: [REFS.fips204],
  },
  {
    name: "crypto-js",
    ecosystem: "npm",
    severity: "high",
    pq_status: "vulnerable",
    reason:
      "Deprecated/abandoned for new work (no active maintainer, several historical advisories); also ships classical-only primitives.",
    recommendation:
      "Replace with WebCrypto / `node:crypto`. For password hashing, prefer `argon2`. No new code on `crypto-js`.",
    references: [REFS.cwe327],
  },
  {
    name: "jsrsasign",
    ecosystem: "npm",
    severity: "medium",
    pq_status: "vulnerable",
    reason: "Pure-JS RSA/ECDSA/X.509 toolkit. All asymmetric primitives are classical.",
    recommendation:
      "Use WebCrypto or `jose`/`@panva/jose`; track ML-DSA/SLH-DSA adoption for signatures.",
    references: [REFS.fips204],
  },
  {
    name: "elliptic",
    ecosystem: "npm",
    severity: "high",
    pq_status: "vulnerable",
    reason:
      "Pure-JS elliptic-curve library (ECDSA / ECDH / EdDSA over secp256k1, P-256, curve25519); every operation is classical ECC broken by Shor's algorithm.",
    recommendation:
      "There is no PQ path in `elliptic`; plan ML-DSA signatures and ML-KEM / hybrid key exchange for the call sites.",
    references: [REFS.fips204],
  },
  {
    name: "tweetnacl",
    ecosystem: "npm",
    severity: "medium",
    pq_status: "vulnerable",
    reason:
      "Ed25519 signatures and X25519 key agreement over Curve25519; both are classical ECC and a harvest-now-decrypt-later target.",
    recommendation:
      "The symmetric `secretbox` parts are quantum-tolerant; migrate the Ed25519/X25519 asymmetric parts to ML-DSA / ML-KEM.",
    references: [REFS.fips203, REFS.fips204],
  },
  {
    name: "secp256k1",
    ecosystem: "npm",
    severity: "medium",
    pq_status: "vulnerable",
    reason:
      "secp256k1 ECDSA/ECDH (the Bitcoin/Ethereum curve); classical elliptic-curve crypto broken by Shor's algorithm.",
    recommendation:
      "Signatures and key agreement need a PQ plan (ML-DSA / ML-KEM); the curve itself has no quantum resistance.",
    references: [REFS.fips204],
  },
  {
    name: "sshpk",
    ecosystem: "npm",
    severity: "medium",
    pq_status: "vulnerable",
    reason:
      "Parses and manipulates SSH RSA/DSA/ECDSA/Ed25519 keys; all supported key types are classical.",
    recommendation:
      "Track OpenSSH PQ key exchange (sntrup761x25519, mlkem768x25519) and rotate host/user keys until PQ signatures are GA.",
    references: [REFS.fips204],
  },
  {
    name: "openpgp",
    ecosystem: "npm",
    severity: "medium",
    pq_status: "vulnerable",
    reason:
      "OpenPGP.js; the RSA / ECDSA / ECDH / EdDSA primitives are classical (post-quantum OpenPGP is still draft/experimental).",
    recommendation:
      "Inventory key types; plan migration as PQC OpenPGP standardizes. Do not assume forward secrecy against harvest-now-decrypt-later.",
    references: [REFS.fips204],
  },
  {
    name: "bcryptjs",
    ecosystem: "npm",
    severity: "low",
    pq_status: "transitional",
    reason:
      "Password hash; bcrypt itself is quantum-tolerant (symmetric), but bcryptjs is pure JS and slower than memory-hard alternatives.",
    recommendation:
      "For new code prefer `argon2` (memory-hard, OWASP-recommended). Bcrypt remains acceptable interim.",
    references: [REFS.ir8547],
  },

  // ---------- python ----------
  {
    name: "pycryptodome",
    ecosystem: "python",
    severity: "medium",
    pq_status: "vulnerable",
    reason:
      "Exposes low-level RSA/DSA/ECC primitives; easy to mis-assemble and entirely classical.",
    recommendation:
      "Use `cryptography` for high-level recipes; track its PQ roadmap (ML-KEM / ML-DSA bindings to OpenSSL 3.5+).",
    references: [REFS.fips204],
  },
  {
    name: "cryptography",
    ecosystem: "python",
    severity: "info",
    pq_status: "transitional",
    reason:
      "Canonical high-level crypto library. Modern versions surface FIPS primitives; PQ algorithms are landing via OpenSSL 3.5+ bindings.",
    recommendation:
      "Stay on a current release; when running on OpenSSL 3.5+, evaluate ML-KEM / ML-DSA bindings as they stabilize.",
    references: [REFS.fips203, REFS.fips204],
  },
  {
    name: "pyjwt",
    ecosystem: "python",
    severity: "high",
    pq_status: "vulnerable",
    reason:
      "Most pyjwt deployments default to HS256 or rely on RS256/ES256 keys, all classical signature schemes.",
    recommendation:
      "If staying on pyjwt, prefer EdDSA and rotate keys; track ML-DSA support for migration.",
    references: [REFS.fips204],
  },
  {
    name: "python-jose",
    ecosystem: "python",
    severity: "high",
    pq_status: "vulnerable",
    reason:
      "JOSE/JWT implementation; the RS256/ES256/PS256 paths rely on classical RSA/ECDSA broken by Shor's algorithm.",
    recommendation:
      "Prefer EdDSA where possible and rotate keys; plan a PQ-signature (ML-DSA) migration for the JWS layer.",
    references: [REFS.fips204],
  },
  {
    name: "rsa",
    ecosystem: "python",
    severity: "high",
    pq_status: "vulnerable",
    reason:
      "Pure-Python RSA package; defaults are weak (e.g. PKCS#1 v1.5) and the entire scheme is broken by CRQCs.",
    recommendation:
      "Drop in favor of `cryptography`; plan PQ-signature migration (ML-DSA via OpenSSL 3.5+).",
    references: [REFS.fips204],
  },
  {
    name: "ecdsa",
    ecosystem: "python",
    severity: "high",
    pq_status: "vulnerable",
    reason: "Pure-Python ECDSA/EdDSA; classical elliptic-curve signatures broken by CRQCs.",
    recommendation:
      "Move to `cryptography`, then plan ML-DSA / SLH-DSA signatures; hybrid (Ed25519 + ML-DSA) is an interim option.",
    references: [REFS.fips204],
  },
  {
    name: "pynacl",
    ecosystem: "python",
    severity: "medium",
    pq_status: "vulnerable",
    reason:
      "Python libsodium bindings; Ed25519 signatures and X25519 key agreement are classical ECC.",
    recommendation:
      "SecretBox (symmetric) is quantum-tolerant; migrate the Ed25519/X25519 asymmetric parts to ML-DSA / ML-KEM.",
    references: [REFS.fips203, REFS.fips204],
  },
  {
    name: "pyopenssl",
    ecosystem: "python",
    severity: "medium",
    pq_status: "vulnerable",
    reason:
      "Wraps OpenSSL X.509/TLS, almost always used with RSA/ECDSA chains today.",
    recommendation:
      "Move TLS / X.509 work to OpenSSL 3.5+ via `cryptography`; pilot hybrid KEMs (X25519MLKEM768).",
    references: [REFS.hybridKex],
  },
  {
    name: "paramiko",
    ecosystem: "python",
    severity: "medium",
    pq_status: "vulnerable",
    reason:
      "SSH client/server with RSA/ECDSA host keys; SSH KEX is classical (curve25519-sha256 etc.).",
    recommendation:
      "Track OpenSSH PQ work (sntrup761x25519, mlkem768x25519); rotate host keys regularly until PQ KEX is GA.",
    references: [REFS.fips204],
  },
  {
    name: "oqs-python",
    ecosystem: "python",
    severity: "info",
    pq_status: "transitional",
    reason:
      "Open Quantum Safe Python bindings (liboqs). Already PQ but treat as transitional, algorithm zoo is pre-NIST-final.",
    recommendation:
      "Prefer NIST-standardized algorithms (ML-KEM, ML-DSA, SLH-DSA) and pin liboqs versions.",
    references: [REFS.fips203, REFS.fips204, REFS.fips205],
  },

  // ---------- cargo ----------
  {
    name: "rsa",
    ecosystem: "cargo",
    severity: "high",
    pq_status: "vulnerable",
    reason: "Pure-Rust RSA crate. RSA is broken by CRQCs.",
    recommendation:
      "Move to ML-KEM (key exchange) / ML-DSA (signatures); the `rustcrypto` `ml-kem` and `ml-dsa` crates are starting points.",
    references: [REFS.fips204, REFS.fips203],
  },
  {
    name: "ecdsa",
    ecosystem: "cargo",
    severity: "high",
    pq_status: "vulnerable",
    reason: "ECDSA signatures are classical and broken by CRQCs.",
    recommendation:
      "Plan migration to ML-DSA or SLH-DSA; hybrid (Ed25519 + ML-DSA) is an interim option.",
    references: [REFS.fips204],
  },
  {
    name: "ed25519-dalek",
    ecosystem: "cargo",
    severity: "high",
    pq_status: "vulnerable",
    reason: "Ed25519 signatures; classical elliptic-curve crypto broken by Shor's algorithm.",
    recommendation:
      "Plan ML-DSA (FIPS 204) signatures; a hybrid Ed25519 + ML-DSA scheme is an interim option.",
    references: [REFS.fips204],
  },
  {
    name: "x25519-dalek",
    ecosystem: "cargo",
    severity: "high",
    pq_status: "vulnerable",
    reason:
      "X25519 Diffie-Hellman key agreement; classical ECC and a prime harvest-now-decrypt-later target.",
    recommendation:
      "Move to ML-KEM (FIPS 203) or a hybrid X25519MLKEM768 construction so session keys resist future decryption.",
    references: [REFS.fips203, REFS.hybridKex],
  },
  {
    name: "p256",
    ecosystem: "cargo",
    severity: "high",
    pq_status: "vulnerable",
    reason: "NIST P-256 ECDSA/ECDH (RustCrypto); classical elliptic-curve crypto broken by CRQCs.",
    recommendation:
      "Plan ML-DSA signatures / ML-KEM key exchange; P-256 has no quantum resistance.",
    references: [REFS.fips204],
  },
  {
    name: "k256",
    ecosystem: "cargo",
    severity: "high",
    pq_status: "vulnerable",
    reason: "secp256k1 ECDSA/ECDH (RustCrypto); classical elliptic-curve crypto broken by CRQCs.",
    recommendation:
      "Plan ML-DSA signatures / ML-KEM key exchange; secp256k1 has no quantum resistance.",
    references: [REFS.fips204],
  },
  {
    name: "ring",
    ecosystem: "cargo",
    severity: "medium",
    pq_status: "vulnerable",
    reason:
      "Stable, audited crypto crate but only exposes classical primitives (RSA, ECDSA, X25519, Ed25519).",
    recommendation:
      "Inventory `ring` call sites; pair with `rustls`/`ml-kem` for hybrid KEM and `ml-dsa` for signatures as they stabilize.",
    references: [REFS.fips204, REFS.fips203],
  },
  {
    name: "openssl",
    ecosystem: "cargo",
    severity: "medium",
    pq_status: "vulnerable",
    reason:
      "Rust bindings to OpenSSL; in practice used with RSA/ECDSA chains. OpenSSL 3.5 ships ML-KEM, but the crate's typical usage is classical.",
    recommendation:
      "Build against OpenSSL 3.5+ and enable hybrid KEMs (X25519MLKEM768); audit signature algorithms for an ML-DSA path.",
    references: [REFS.hybridKex, REFS.fips204],
  },
  {
    name: "rustls",
    ecosystem: "cargo",
    fixedIn: "0.23.0",
    severity: "medium",
    pq_status: "vulnerable",
    reason:
      "Modern TLS stack; the X25519MLKEM768 hybrid group is available from 0.23, but older pinned releases are classical-only.",
    recommendation:
      "Upgrade to rustls >= 0.23 with hybrid KEM support (X25519MLKEM768) and enable it server- and client-side.",
    references: [REFS.hybridKex, REFS.fips203],
  },
  {
    name: "oqs",
    ecosystem: "cargo",
    severity: "info",
    pq_status: "transitional",
    reason:
      "Open Quantum Safe Rust bindings, already PQ, but pre-NIST-final algorithm set; treat as transitional.",
    recommendation:
      "Prefer NIST-standardized algorithms (ML-KEM, ML-DSA, SLH-DSA) once available in stable form.",
    references: [REFS.fips203, REFS.fips204, REFS.fips205],
  },
  {
    name: "pqcrypto",
    ecosystem: "cargo",
    severity: "info",
    pq_status: "transitional",
    reason:
      "PQClean Rust bindings; covers multiple PQ algorithms but pre-standardization variants linger.",
    recommendation: "Pin to NIST-standardized variants (ML-KEM, ML-DSA, SLH-DSA).",
    references: [REFS.fips203, REFS.fips204, REFS.fips205],
  },
];

/** Lookup helper. Pure. */
export function lookupEntry(name: string, ecosystem: Ecosystem): RegistryEntry | undefined {
  return REGISTRY.find((entry) => entry.name === name && entry.ecosystem === ecosystem);
}
