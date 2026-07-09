/**
 * Dependency-audit registry.
 *
 * Pure-data module: each entry describes a single (name, ecosystem) pair that
 * we want to flag, along with the PQ posture and the migration recommendation
 * to surface in the report. No I/O.
 *
 * Edit this list as the ecosystem moves — version ranges intentionally default
 * to "*" because authoritative per-version PQ guidance is still emerging.
 * When unsure of a version cutoff, leave it "*" and explain in `reason`.
 *
 * Sources used while seeding v0.1:
 *   - NIST PQC migration guidance (FIPS 203/204/205, IR 8547 draft).
 *   - CNSA 2.0 (NSA, 2022) — RSA/ECDSA deprecation timeline.
 *   - Package maintainers' own README/changelogs (read 2026-05).
 */
import type { PqStatus, Severity } from "../../report";

export type Ecosystem = "npm" | "python" | "cargo";

export interface RegistryEntry {
  name: string;
  ecosystem: Ecosystem;
  /** Semver / PEP440 / cargo range. Defaults to "*" — see file header. */
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
  },
  {
    name: "node-rsa",
    ecosystem: "npm",
    severity: "high",
    pq_status: "vulnerable",
    reason: "Pure-JS RSA implementation; RSA key exchange/signatures are broken by CRQCs.",
    recommendation:
      "Migrate to native `node:crypto` and plan hybrid (X25519+ML-KEM) key exchange or ML-DSA signatures.",
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
  },
  {
    name: "jsrsasign",
    ecosystem: "npm",
    severity: "medium",
    pq_status: "vulnerable",
    reason: "Pure-JS RSA/ECDSA/X.509 toolkit. All asymmetric primitives are classical.",
    recommendation:
      "Use WebCrypto or `jose`/`@panva/jose`; track ML-DSA/SLH-DSA adoption for signatures.",
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
  },
  {
    name: "pyjwt",
    ecosystem: "python",
    severity: "high",
    pq_status: "vulnerable",
    reason:
      "Most pyjwt deployments default to HS256 or rely on RS256/ES256 keys — all classical signature schemes.",
    recommendation:
      "If staying on pyjwt, prefer EdDSA and rotate keys; track ML-DSA support for migration.",
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
  },
  {
    name: "pyopenssl",
    ecosystem: "python",
    severity: "medium",
    pq_status: "vulnerable",
    reason:
      "Wraps OpenSSL X.509/TLS — almost always used with RSA/ECDSA chains today.",
    recommendation:
      "Move TLS / X.509 work to OpenSSL 3.5+ via `cryptography`; pilot hybrid KEMs (X25519MLKEM768).",
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
  },
  {
    name: "oqs-python",
    ecosystem: "python",
    severity: "info",
    pq_status: "transitional",
    reason:
      "Open Quantum Safe Python bindings (liboqs). Already PQ but treat as transitional — algorithm zoo is pre-NIST-final.",
    recommendation:
      "Prefer NIST-standardized algorithms (ML-KEM, ML-DSA, SLH-DSA) and pin liboqs versions.",
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
  },
  {
    name: "ecdsa",
    ecosystem: "cargo",
    severity: "high",
    pq_status: "vulnerable",
    reason: "ECDSA signatures are classical and broken by CRQCs.",
    recommendation:
      "Plan migration to ML-DSA or SLH-DSA; hybrid (Ed25519 + ML-DSA) is an interim option.",
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
  },
  {
    name: "oqs",
    ecosystem: "cargo",
    severity: "info",
    pq_status: "transitional",
    reason:
      "Open Quantum Safe Rust bindings — already PQ, but pre-NIST-final algorithm set; treat as transitional.",
    recommendation:
      "Prefer NIST-standardized algorithms (ML-KEM, ML-DSA, SLH-DSA) once available in stable form.",
  },
  {
    name: "pqcrypto",
    ecosystem: "cargo",
    severity: "info",
    pq_status: "transitional",
    reason:
      "PQClean Rust bindings; covers multiple PQ algorithms but pre-standardization variants linger.",
    recommendation: "Pin to NIST-standardized variants (ML-KEM, ML-DSA, SLH-DSA).",
  },
];

/** Lookup helper. Pure. */
export function lookupEntry(name: string, ecosystem: Ecosystem): RegistryEntry | undefined {
  return REGISTRY.find((entry) => entry.name === name && entry.ecosystem === ecosystem);
}
