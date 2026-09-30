/**
 * Dependency-audit registry.
 *
 * Pure-data module: each entry describes a single (name, ecosystem) pair that
 * we want to flag, along with the PQ posture, what the library's flagged
 * primitives are used for, the migration recommendation, and at least one
 * provenance reference explaining why it is flagged. No I/O.
 *
 * Inclusion rule: add a (name, ecosystem) only for a library that either ships
 * or wraps a classical asymmetric primitive at risk from Shor (RSA / DSA /
 * ECDSA / ECDH / Ed25519 / X25519 / secp256k1), or is a post-quantum library
 * (mark it transitional). The one exception is a discontinued crypto toolkit
 * whose use is itself a classical finding (crypto-js); it is flagged with
 * `pq_status: "unknown"` because its quantum posture depends on which of its
 * algorithms the code calls. Every vulnerable/transitional entry carries >= 1
 * reference. Set `fixedIn` ONLY when a specific released version added a
 * PQ-relevant capability that flips the assessment, and only when the release
 * notes say so; libraries classical by nature at every version omit it and are
 * flagged regardless of version.
 *
 * `usage` drives the risk engine: an entry whose primitives establish keys or
 * encrypt lands in the harvest-now-decrypt-later ledger, one that only signs or
 * authenticates is forge-later. List every use the library offers, because the
 * scanner cannot tell which API a codebase calls. `algorithms` names the
 * flagged primitives the library provides, for the CBOM.
 *
 * Sources used while seeding and last review (2026-10):
 *   - NIST PQC standards (FIPS 203/204/205) and IR 8547 (migration).
 *   - CNSA 2.0 (NSA, 2022), RSA/ECDSA deprecation timeline.
 *   - RFC 10024 (ECDHE-MLKEM hybrids for TLS 1.3), RFC 9964 (ML-DSA for JOSE
 *     and COSE), RFC 9980 (post-quantum OpenPGP).
 *   - Package maintainers' own README/changelogs: rustls 0.23.22 and 0.23.27
 *     release notes, pyca/cryptography CHANGELOG (47.0.0, 48.0.0), the
 *     paramiko changelog, and the liboqs README.
 */
import { REFS } from "../../crypto";
import type { CryptoUsage, PqStatus, Reference, Severity } from "../../report";

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
  /** What the library's flagged primitives do; see the file header. */
  usage: CryptoUsage[];
  /** Canonical names of the flagged primitives the library provides (CBOM `provides`). */
  algorithms: string[];
  reason: string;
  recommendation: string;
  /** Provenance: standards / advisories backing this entry's classification. */
  references?: Reference[];
}

/** Standards the registry cites that the shared knowledge base does not carry. */
const STANDARDS = {
  joseMlDsa: { label: "RFC 9964 (ML-DSA for JOSE and COSE)", url: "https://www.rfc-editor.org/rfc/rfc9964" },
  openpgpPqc: { label: "RFC 9980 (Post-Quantum Cryptography in OpenPGP)", url: "https://www.rfc-editor.org/rfc/rfc9980" },
  tlsHybrid: {
    label: "RFC 10024 (PQ/T hybrid ECDHE-MLKEM key agreement for TLS 1.3)",
    url: "https://www.rfc-editor.org/rfc/rfc10024",
  },
  liboqs: { label: "liboqs README (not recommended for production use)", url: "https://github.com/open-quantum-safe/liboqs" },
} as const satisfies Record<string, Reference>;

/** Shared text for the JOSE libraries: RFC 9964 is the PQ path, and EdDSA/RSA-PSS are not one. */
const JOSE_RECOMMENDATION =
  "Plan ML-DSA-signed tokens (RFC 9964 registers ML-DSA-44/65/87 for JOSE) and keep issuer keys rotatable; EdDSA, RSA-PSS and ECDSA are all equally broken by Shor's algorithm, so switching among them is not a migration. HMAC (HS*) tokens with a >= 256-bit secret are not Shor-exposed.";

export const REGISTRY: readonly RegistryEntry[] = [
  // ---------- npm ----------
  {
    name: "jsonwebtoken",
    ecosystem: "npm",
    severity: "high",
    pq_status: "vulnerable",
    usage: ["authentication", "signature"],
    algorithms: ["RSA", "ECDSA", "HMAC"],
    reason:
      "Widely used JWT (JWS) library; its RS*/PS*/ES* algorithms rely on classical RSA/ECDSA broken by Shor's algorithm, and it has no post-quantum algorithm.",
    recommendation: `${JOSE_RECOMMENDATION} jsonwebtoken ships no ML-DSA support, so plan a library change (e.g. \`jose\` once it supports RFC 9964).`,
    references: [REFS.fips204, STANDARDS.joseMlDsa],
  },
  {
    name: "node-rsa",
    ecosystem: "npm",
    severity: "high",
    pq_status: "vulnerable",
    usage: ["encryption", "signature"],
    algorithms: ["RSA"],
    reason:
      "Pure-JS RSA implementation used for both encryption and signatures; data encrypted with it today is a harvest-now-decrypt-later target.",
    recommendation:
      "Migrate to native `node:crypto`; replace RSA encryption with ML-KEM (FIPS 203) based key establishment and RSA signatures with ML-DSA (FIPS 204).",
    references: [REFS.fips203, REFS.fips204],
  },
  {
    name: "node-forge",
    ecosystem: "npm",
    severity: "medium",
    pq_status: "vulnerable",
    usage: ["key-establishment", "encryption", "signature"],
    algorithms: ["RSA", "Ed25519"],
    reason:
      "Legacy crypto toolkit (a JS TLS implementation, X.509, PKCS#1/#7/#12, RSA, Ed25519) commonly used in browsers/Electron; ships only classical asymmetric primitives.",
    recommendation:
      "Move primitives to native `node:crypto` (or WebCrypto); use ML-KEM (FIPS 203) or a hybrid KEM for key transport and encryption, and ML-DSA (FIPS 204) for signatures.",
    references: [REFS.fips203, REFS.fips204],
  },
  {
    name: "crypto-js",
    ecosystem: "npm",
    severity: "medium",
    pq_status: "unknown",
    usage: ["encryption", "hashing"],
    algorithms: ["AES", "3DES", "DES", "RC4", "MD5", "SHA-1"],
    reason:
      "Discontinued symmetric-only toolkit (its maintainers stopped development in 2023) that ships classically broken options (DES, TripleDES, RC4, MD5, SHA-1) next to AES. It has no asymmetric primitives, so its quantum posture depends on which algorithms the code calls.",
    recommendation:
      "Replace with WebCrypto / `node:crypto` (AES-256-GCM, SHA-256+). For password hashing, prefer `argon2`. No new code on `crypto-js`.",
    references: [REFS.cwe327],
  },
  {
    name: "jsrsasign",
    ecosystem: "npm",
    severity: "medium",
    pq_status: "vulnerable",
    usage: ["signature", "encryption"],
    algorithms: ["RSA", "ECDSA", "DSA"],
    reason: "Pure-JS RSA/ECDSA/DSA/X.509 toolkit, including RSA encryption. All asymmetric primitives are classical.",
    recommendation:
      "Use WebCrypto or `jose`; plan ML-DSA / SLH-DSA (FIPS 204 / 205) for signatures and ML-KEM (FIPS 203) wherever RSA encryption is used.",
    references: [REFS.fips204, REFS.fips203],
  },
  {
    name: "elliptic",
    ecosystem: "npm",
    severity: "high",
    pq_status: "vulnerable",
    usage: ["signature", "key-establishment"],
    algorithms: ["ECDSA", "ECDH", "Ed25519"],
    reason:
      "Pure-JS elliptic-curve library (ECDSA / ECDH / EdDSA over secp256k1, P-256, curve25519); every operation is classical ECC broken by Shor's algorithm.",
    recommendation:
      "There is no PQ path in `elliptic`; plan ML-DSA signatures and ML-KEM / hybrid key exchange for the call sites.",
    references: [REFS.fips204, REFS.fips203],
  },
  {
    name: "tweetnacl",
    ecosystem: "npm",
    severity: "medium",
    pq_status: "vulnerable",
    usage: ["key-establishment", "encryption", "signature"],
    algorithms: ["X25519", "Ed25519"],
    reason:
      "Ed25519 signatures and X25519 key agreement (the `box` construction) over Curve25519; both are classical ECC, and `box` ciphertexts are a harvest-now-decrypt-later target.",
    recommendation:
      "The symmetric `secretbox` parts are quantum-tolerant; migrate the X25519 `box` key agreement to ML-KEM (or a hybrid) and Ed25519 signatures to ML-DSA.",
    references: [REFS.fips203, REFS.fips204],
  },
  {
    name: "secp256k1",
    ecosystem: "npm",
    severity: "medium",
    pq_status: "vulnerable",
    usage: ["signature", "key-establishment"],
    algorithms: ["ECDSA-secp256k1", "ECDH-secp256k1"],
    reason:
      "secp256k1 ECDSA/ECDH (the Bitcoin/Ethereum curve); classical elliptic-curve crypto broken by Shor's algorithm.",
    recommendation:
      "Signatures and key agreement need a PQ plan (ML-DSA / ML-KEM); the curve itself has no quantum resistance.",
    references: [REFS.fips204, REFS.fips203],
  },
  {
    name: "sshpk",
    ecosystem: "npm",
    severity: "medium",
    pq_status: "vulnerable",
    usage: ["authentication", "signature", "key-establishment"],
    algorithms: ["RSA", "DSA", "ECDSA", "Ed25519"],
    reason:
      "Parses, signs and verifies with SSH RSA/DSA/ECDSA/Ed25519 keys and offers ECDH/X25519 Diffie-Hellman over them; all supported key types are classical.",
    recommendation:
      "Inventory host/user keys and plan rotation to post-quantum signature keys as SSH standardizes them. Session confidentiality is a separate question: OpenSSH has defaulted to hybrid PQ key exchange since 9.0 (sntrup761x25519) and 10.0 (mlkem768x25519).",
    references: [REFS.fips204],
  },
  {
    name: "openpgp",
    ecosystem: "npm",
    severity: "medium",
    pq_status: "vulnerable",
    usage: ["encryption", "key-establishment", "signature"],
    algorithms: ["RSA", "ECDSA", "ECDH", "Ed25519", "X25519"],
    reason:
      "OpenPGP.js; its released RSA / ECDH / X25519 encryption and RSA / ECDSA / EdDSA signatures are classical. Encrypted messages are the textbook harvest-now-decrypt-later case.",
    recommendation:
      "Post-quantum OpenPGP is standardized (RFC 9980: composite ML-KEM-768+X25519 encryption and ML-DSA-65+Ed25519 signatures); adopt it once OpenPGP.js ships it in a release, re-encrypt long-lived data under it, and inventory key types until then.",
    references: [REFS.fips203, REFS.fips204, STANDARDS.openpgpPqc],
  },

  // ---------- python ----------
  {
    name: "pycryptodome",
    ecosystem: "python",
    severity: "medium",
    pq_status: "vulnerable",
    usage: ["encryption", "signature"],
    algorithms: ["RSA", "DSA", "ECDSA", "Ed25519"],
    reason:
      "Exposes low-level RSA (including OAEP encryption), DSA and ECC primitives; easy to mis-assemble and entirely classical.",
    recommendation:
      "Use `cryptography` (>= 48.0.0 exposes ML-KEM and ML-DSA with its standard wheels) for high-level recipes and plan ML-KEM / ML-DSA replacements for the RSA/ECC call sites.",
    references: [REFS.fips203, REFS.fips204],
  },
  {
    name: "cryptography",
    ecosystem: "python",
    fixedIn: "48.0.0",
    severity: "info",
    pq_status: "transitional",
    usage: ["encryption", "key-establishment", "signature"],
    algorithms: ["RSA", "ECDSA", "ECDH", "Ed25519", "X25519"],
    reason:
      "Canonical high-level crypto library. ML-KEM and ML-DSA arrived in 47.0.0 for AWS-LC/BoringSSL builds and in 48.0.0 for OpenSSL 3.5+, which puts them in the standard wheels; its RSA/ECC APIs remain classical.",
    recommendation:
      "Stay on >= 48.0.0 and move key establishment to ML-KEM (or a hybrid) and signatures to ML-DSA where the protocol allows.",
    references: [REFS.fips203, REFS.fips204],
  },
  {
    name: "pyjwt",
    ecosystem: "python",
    severity: "high",
    pq_status: "vulnerable",
    usage: ["authentication", "signature"],
    algorithms: ["RSA", "ECDSA", "Ed25519", "HMAC"],
    reason:
      "JWT (JWS) library whose RS*/PS*/ES*/EdDSA algorithms are all classical signature schemes; it has no post-quantum algorithm.",
    recommendation: JOSE_RECOMMENDATION,
    references: [REFS.fips204, STANDARDS.joseMlDsa],
  },
  {
    name: "python-jose",
    ecosystem: "python",
    severity: "high",
    pq_status: "vulnerable",
    usage: ["authentication", "signature", "encryption"],
    algorithms: ["RSA", "ECDSA", "HMAC"],
    reason:
      "JOSE/JWT implementation; the RS*/ES*/PS* signatures and RSA-based JWE key management rely on classical RSA/ECDSA broken by Shor's algorithm.",
    recommendation: `${JOSE_RECOMMENDATION} RSA-encrypted JWEs are a harvest-now-decrypt-later exposure; move them to ML-KEM based key management.`,
    references: [REFS.fips204, REFS.fips203, STANDARDS.joseMlDsa],
  },
  {
    name: "rsa",
    ecosystem: "python",
    severity: "high",
    pq_status: "vulnerable",
    usage: ["encryption", "signature"],
    algorithms: ["RSA"],
    reason:
      "Pure-Python RSA package for encryption and signatures; defaults are weak (e.g. PKCS#1 v1.5) and the entire scheme is broken by CRQCs.",
    recommendation:
      "Drop in favor of `cryptography`; replace RSA encryption with ML-KEM (FIPS 203) and RSA signatures with ML-DSA (FIPS 204).",
    references: [REFS.fips203, REFS.fips204],
  },
  {
    name: "ecdsa",
    ecosystem: "python",
    severity: "high",
    pq_status: "vulnerable",
    usage: ["signature", "key-establishment"],
    algorithms: ["ECDSA", "ECDH", "Ed25519"],
    reason: "Pure-Python ECDSA/EdDSA signatures and ECDH; classical elliptic-curve crypto broken by CRQCs.",
    recommendation:
      "Move to `cryptography`, then plan ML-DSA / SLH-DSA signatures and ML-KEM key establishment; hybrid (Ed25519 + ML-DSA) is an interim option.",
    references: [REFS.fips204, REFS.fips203],
  },
  {
    name: "pynacl",
    ecosystem: "python",
    severity: "medium",
    pq_status: "vulnerable",
    usage: ["key-establishment", "encryption", "signature"],
    algorithms: ["X25519", "Ed25519"],
    reason:
      "Python libsodium bindings; Ed25519 signatures and X25519 key agreement (`Box`, `SealedBox`) are classical ECC, and boxed ciphertexts are a harvest-now-decrypt-later target.",
    recommendation:
      "SecretBox (symmetric) is quantum-tolerant; migrate `Box`/`SealedBox` to ML-KEM based key establishment and Ed25519 signatures to ML-DSA.",
    references: [REFS.fips203, REFS.fips204],
  },
  {
    name: "pyopenssl",
    ecosystem: "python",
    severity: "medium",
    pq_status: "vulnerable",
    usage: ["key-establishment", "signature"],
    algorithms: ["RSA", "ECDSA", "ECDH"],
    reason: "Wraps OpenSSL X.509/TLS, almost always used with RSA/ECDSA chains and classical key exchange today.",
    recommendation:
      "Move TLS / X.509 work to `cryptography` or the standard `ssl` module on OpenSSL 3.5+, and enable the hybrid X25519MLKEM768 group.",
    references: [REFS.hybridKex, STANDARDS.tlsHybrid],
  },
  {
    name: "paramiko",
    ecosystem: "python",
    severity: "medium",
    pq_status: "vulnerable",
    usage: ["key-establishment", "authentication"],
    algorithms: ["X25519", "ECDH", "DH", "RSA", "ECDSA", "Ed25519"],
    // fixedIn deliberately unset: mlkem768x25519-sha256 support is merged on
    // paramiko's development branch but not in any release up to 5.0.0.
    reason:
      "SSH client/server whose released versions (through 5.0.0) negotiate only classical key exchange (curve25519-sha256, ECDH, finite-field DH) with RSA/ECDSA/Ed25519 host and user keys.",
    recommendation:
      "Upgrade to the first paramiko release that ships mlkem768x25519-sha256 (merged upstream, interoperable with OpenSSH 10.0+, and requiring a `cryptography` build with ML-KEM), and plan host/user key rotation separately.",
    references: [REFS.fips203, REFS.fips204],
  },
  {
    name: "liboqs-python",
    ecosystem: "python",
    severity: "info",
    pq_status: "transitional",
    usage: ["key-establishment", "signature"],
    algorithms: ["ML-KEM", "ML-DSA", "SLH-DSA"],
    reason:
      "Open Quantum Safe Python bindings (liboqs). They include the NIST-standardized ML-KEM, ML-DSA and SLH-DSA alongside experimental candidates, and the OQS project does not recommend liboqs for production or for protecting sensitive data.",
    recommendation:
      "Use only the standardized algorithms (ML-KEM, ML-DSA, SLH-DSA), pin liboqs, and move production traffic to a maintained provider (e.g. OpenSSL 3.5+ or `cryptography`).",
    references: [REFS.fips203, REFS.fips204, REFS.fips205, STANDARDS.liboqs],
  },

  // ---------- cargo ----------
  {
    name: "rsa",
    ecosystem: "cargo",
    severity: "high",
    pq_status: "vulnerable",
    usage: ["encryption", "signature"],
    algorithms: ["RSA"],
    reason: "Pure-Rust RSA crate (OAEP / PKCS#1 v1.5 encryption and signatures). RSA is broken by CRQCs.",
    recommendation:
      "Move to ML-KEM (key exchange) / ML-DSA (signatures); the `rustcrypto` `ml-kem` and `ml-dsa` crates are starting points.",
    references: [REFS.fips204, REFS.fips203],
  },
  {
    name: "ecdsa",
    ecosystem: "cargo",
    severity: "high",
    pq_status: "vulnerable",
    usage: ["signature"],
    algorithms: ["ECDSA"],
    reason: "ECDSA signatures are classical and broken by CRQCs.",
    recommendation: "Plan migration to ML-DSA or SLH-DSA; hybrid (Ed25519 + ML-DSA) is an interim option.",
    references: [REFS.fips204],
  },
  {
    name: "ed25519-dalek",
    ecosystem: "cargo",
    severity: "high",
    pq_status: "vulnerable",
    usage: ["signature"],
    algorithms: ["Ed25519"],
    reason: "Ed25519 signatures; classical elliptic-curve crypto broken by Shor's algorithm.",
    recommendation: "Plan ML-DSA (FIPS 204) signatures; a hybrid Ed25519 + ML-DSA scheme is an interim option.",
    references: [REFS.fips204],
  },
  {
    name: "x25519-dalek",
    ecosystem: "cargo",
    severity: "high",
    pq_status: "vulnerable",
    usage: ["key-establishment"],
    algorithms: ["X25519"],
    reason:
      "X25519 Diffie-Hellman key agreement; classical ECC and a prime harvest-now-decrypt-later target.",
    recommendation:
      "Move to ML-KEM (FIPS 203) or a hybrid X25519MLKEM768 construction so session keys resist future decryption.",
    references: [REFS.fips203, STANDARDS.tlsHybrid],
  },
  {
    name: "p256",
    ecosystem: "cargo",
    severity: "high",
    pq_status: "vulnerable",
    usage: ["signature", "key-establishment"],
    algorithms: ["ECDSA-P-256", "ECDH-P-256"],
    reason: "NIST P-256 ECDSA/ECDH (RustCrypto); classical elliptic-curve crypto broken by CRQCs.",
    recommendation: "Plan ML-DSA signatures / ML-KEM key exchange; P-256 has no quantum resistance.",
    references: [REFS.fips204, REFS.fips203],
  },
  {
    name: "k256",
    ecosystem: "cargo",
    severity: "high",
    pq_status: "vulnerable",
    usage: ["signature", "key-establishment"],
    algorithms: ["ECDSA-secp256k1", "ECDH-secp256k1"],
    reason: "secp256k1 ECDSA/ECDH (RustCrypto); classical elliptic-curve crypto broken by CRQCs.",
    recommendation: "Plan ML-DSA signatures / ML-KEM key exchange; secp256k1 has no quantum resistance.",
    references: [REFS.fips204, REFS.fips203],
  },
  {
    name: "ring",
    ecosystem: "cargo",
    severity: "medium",
    pq_status: "vulnerable",
    usage: ["key-establishment", "signature"],
    algorithms: ["RSA", "ECDSA", "Ed25519", "X25519", "ECDH"],
    reason:
      "Stable, audited crypto crate but only exposes classical asymmetric primitives (RSA, ECDSA, Ed25519, X25519/ECDH agreement).",
    recommendation:
      "Inventory `ring` call sites; for TLS, use rustls with the aws-lc-rs provider (the ring provider has no post-quantum group), and use `ml-kem` / `ml-dsa` crates elsewhere.",
    references: [REFS.fips204, REFS.fips203],
  },
  {
    name: "openssl",
    ecosystem: "cargo",
    severity: "medium",
    pq_status: "vulnerable",
    usage: ["key-establishment", "encryption", "signature"],
    algorithms: ["RSA", "ECDSA", "ECDH", "Ed25519", "X25519", "DH"],
    reason:
      "Rust bindings to OpenSSL; in practice used with RSA/ECDSA chains. OpenSSL 3.5 ships ML-KEM and ML-DSA, but the crate's typical usage is classical.",
    recommendation:
      "Build against OpenSSL 3.5+ and enable the hybrid X25519MLKEM768 group; audit signature algorithms for an ML-DSA path.",
    references: [REFS.hybridKex, STANDARDS.tlsHybrid, REFS.fips204],
  },
  {
    name: "rustls",
    ecosystem: "cargo",
    // 0.23.22 (2025-01-30) moved X25519MLKEM768 into the core crate for the
    // aws-lc-rs provider; 0.23.27 (2025-05-05) made it the preferred group by
    // default. 0.23.0 (2024-02-29) predates FIPS 203 and shipped no PQ group.
    fixedIn: "0.23.22",
    severity: "medium",
    pq_status: "vulnerable",
    usage: ["key-establishment", "signature"],
    algorithms: ["X25519", "ECDH", "RSA", "ECDSA", "Ed25519"],
    reason:
      "Modern TLS stack; the X25519MLKEM768 hybrid group is available from 0.23.22 with the aws-lc-rs provider (preferred by default from 0.23.27). Older releases, and the ring provider at any version, are classical-only.",
    recommendation:
      "Upgrade to rustls >= 0.23.27 with the aws-lc-rs provider (or >= 0.23.22 with the `prefer-post-quantum` feature) so X25519MLKEM768 is negotiated first, on both client and server.",
    references: [REFS.hybridKex, STANDARDS.tlsHybrid, REFS.fips203],
  },
  {
    name: "oqs",
    ecosystem: "cargo",
    severity: "info",
    pq_status: "transitional",
    usage: ["key-establishment", "signature"],
    algorithms: ["ML-KEM", "ML-DSA", "SLH-DSA"],
    reason:
      "Open Quantum Safe Rust bindings (liboqs); they carry the NIST-standardized ML-KEM and ML-DSA next to experimental candidates, and the OQS project does not recommend liboqs for production use.",
    recommendation:
      "Enable only the standardized algorithms (the `ml_kem` / `ml_dsa` features) and plan a move to a production-grade provider.",
    references: [REFS.fips203, REFS.fips204, REFS.fips205, STANDARDS.liboqs],
  },
  {
    name: "pqcrypto",
    ecosystem: "cargo",
    severity: "info",
    pq_status: "transitional",
    usage: ["key-establishment", "signature"],
    algorithms: ["ML-KEM", "ML-DSA"],
    reason:
      "PQClean-based Rust bindings; they cover the standardized ML-KEM and ML-DSA alongside non-standardized schemes.",
    recommendation: "Pin to the NIST-standardized variants (ML-KEM, ML-DSA, SLH-DSA).",
    references: [REFS.fips203, REFS.fips204, REFS.fips205],
  },
];

/** Lookup helper. Pure. */
export function lookupEntry(name: string, ecosystem: Ecosystem): RegistryEntry | undefined {
  return REGISTRY.find((entry) => entry.name === name && entry.ecosystem === ecosystem);
}

/** The stable rule id of a dependency finding: `deps/<ecosystem>-<name>`. */
export function depsRuleId(entry: Pick<RegistryEntry, "ecosystem" | "name">): string {
  return `deps/${entry.ecosystem}-${entry.name}`;
}

/**
 * The registry entry a dependency rule id refers to, by exact match against
 * {@link depsRuleId}, so consumers never re-parse the library name out of it.
 */
export function entryForRuleId(ruleId: string | undefined): RegistryEntry | undefined {
  if (!ruleId) return undefined;
  return REGISTRY.find((entry) => depsRuleId(entry) === ruleId);
}
