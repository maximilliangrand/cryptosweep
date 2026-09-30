/**
 * CycloneDX 1.6 Cryptography Bill of Materials (CBOM) emitter.
 *
 * A CBOM is the standardized, machine-readable inventory of the cryptographic
 * assets a system uses. Emitting one is what lets cryptosweep's output flow into
 * the SBOM / compliance / risk toolchains organizations already run, rather than
 * being one more bespoke report.
 *
 * What goes in, and only from structured finding fields (never from titles):
 *   - one `algorithm` asset per distinct algorithm, typed with the CycloneDX
 *     primitive vocabulary, its OID (the certificate's own signature OID when
 *     the scanner read one), and its NIST quantum security category;
 *   - one `certificate` asset per parsed certificate, linked to its signature
 *     algorithm and to its subject public key;
 *   - key material (`related-crypto-material`) for committed private keys and
 *     embedded public keys, one per occurrence;
 *   - the negotiated `protocol`, when a live session was observed;
 *   - flagged dependencies as `library` components that `provide` the
 *     algorithms the registry lists for them.
 * Status findings ("hybrid key exchange not offered", "expires in 30 days") are
 * not assets and stay in the report and SARIF.
 *
 * Spec: https://cyclonedx.org/docs/1.6/json/ (cryptoProperties)
 */
import { createHash } from "node:crypto";
import { resolveUsage } from "../model/risk";
import { sanitizeText } from "../report";
import type { CertificateDetails, CryptoUsage, Finding, PqStatus, Report, Severity } from "../report";
import { entryForRuleId } from "../scanners/deps/registry";
import { VERSION } from "../version";
import { REPOSITORY_URL } from "./sarif";

/** CycloneDX 1.6 `algorithmProperties.primitive` values. */
type Primitive =
  | "signature"
  | "kem"
  | "key-agree"
  | "pke"
  | "hash"
  | "block-cipher"
  | "stream-cipher"
  | "mac"
  | "ae"
  | "other"
  | "unknown";

type Mode = "cbc" | "ecb" | "ccm" | "gcm" | "cfb" | "ofb" | "ctr";

export interface AlgorithmDescriptor {
  primitive: Primitive;
  /**
   * NIST PQC security category (0 = meets none of them, i.e. broken by a CRQC
   * or classically; 1..5 = category). Omitted when it depends on a parameter
   * the label does not carry (bare `AES`, an HMAC key of unknown length).
   */
  nistQuantumSecurityLevel?: number;
  /** Classical security strength in bits (SP 800-57 Part 1, Table 2), when standard. */
  classicalSecurityLevel?: number;
  oid?: string;
  /** Parameter-set identifier as CycloneDX defines it: `2048`, `65`, `768`, `SHA2-128s`. */
  parameterSetIdentifier?: string;
  /** Curve name (SECG names, as CycloneDX recommends via neuromancer.sk/std). */
  curve?: string;
  mode?: Mode;
}

/** Signature-algorithm OIDs by the names the ASN.1 reader assigns them (RFC 3279/4055/5758/8410, NIST CSOR). */
const SIGNATURE_OIDS: Readonly<Record<string, string>> = {
  md2WithRSAEncryption: "1.2.840.113549.1.1.2",
  md4WithRSAEncryption: "1.2.840.113549.1.1.3",
  md5WithRSAEncryption: "1.2.840.113549.1.1.4",
  sha1WithRSAEncryption: "1.2.840.113549.1.1.5",
  sha224WithRSAEncryption: "1.2.840.113549.1.1.14",
  sha256WithRSAEncryption: "1.2.840.113549.1.1.11",
  sha384WithRSAEncryption: "1.2.840.113549.1.1.12",
  sha512WithRSAEncryption: "1.2.840.113549.1.1.13",
  rsassaPss: "1.2.840.113549.1.1.10",
  dsaWithSHA1: "1.2.840.10040.4.3",
  dsaWithSHA224: "2.16.840.1.101.3.4.3.1",
  dsaWithSHA256: "2.16.840.1.101.3.4.3.2",
  ecdsaWithSHA1: "1.2.840.10045.4.1",
  ecdsaWithSHA224: "1.2.840.10045.4.3.1",
  ecdsaWithSHA256: "1.2.840.10045.4.3.2",
  ecdsaWithSHA384: "1.2.840.10045.4.3.3",
  ecdsaWithSHA512: "1.2.840.10045.4.3.4",
};

/** ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) OIDs, NIST CSOR sigAlgs arc. */
const PQ_SIGNATURE_OIDS: Readonly<Record<string, string>> = {
  "ML-DSA-44": "2.16.840.1.101.3.4.3.17",
  "ML-DSA-65": "2.16.840.1.101.3.4.3.18",
  "ML-DSA-87": "2.16.840.1.101.3.4.3.19",
  "SLH-DSA-SHA2-128s": "2.16.840.1.101.3.4.3.20",
  "SLH-DSA-SHA2-128f": "2.16.840.1.101.3.4.3.21",
  "SLH-DSA-SHA2-192s": "2.16.840.1.101.3.4.3.22",
  "SLH-DSA-SHA2-192f": "2.16.840.1.101.3.4.3.23",
  "SLH-DSA-SHA2-256s": "2.16.840.1.101.3.4.3.24",
  "SLH-DSA-SHA2-256f": "2.16.840.1.101.3.4.3.25",
  "SLH-DSA-SHAKE-128s": "2.16.840.1.101.3.4.3.26",
  "SLH-DSA-SHAKE-128f": "2.16.840.1.101.3.4.3.27",
  "SLH-DSA-SHAKE-192s": "2.16.840.1.101.3.4.3.28",
  "SLH-DSA-SHAKE-192f": "2.16.840.1.101.3.4.3.29",
  "SLH-DSA-SHAKE-256s": "2.16.840.1.101.3.4.3.30",
  "SLH-DSA-SHAKE-256f": "2.16.840.1.101.3.4.3.31",
};

/** ML-KEM (FIPS 203) OIDs, NIST CSOR kems arc, and NIST categories per parameter set. */
const ML_KEM: Readonly<Record<string, { oid: string; level: number }>> = {
  "512": { oid: "2.16.840.1.101.3.4.4.1", level: 1 },
  "768": { oid: "2.16.840.1.101.3.4.4.2", level: 3 },
  "1024": { oid: "2.16.840.1.101.3.4.4.3", level: 5 },
};

/** NIST categories for ML-DSA parameter sets (FIPS 204 Table 1). */
const ML_DSA_LEVEL: Readonly<Record<string, number>> = { "44": 2, "65": 3, "87": 5 };

/** NIST categories for SLH-DSA by security parameter (FIPS 205 Table 2). */
const SLH_DSA_LEVEL: Readonly<Record<string, number>> = { "128": 1, "192": 3, "256": 5 };

/** Curves by the friendly and OpenSSL names the scanners emit: SECG name, key OID, classical strength. */
const CURVES: Readonly<Record<string, { name: string; oid: string; bits: number }>> = {
  "p-256": { name: "secp256r1", oid: "1.2.840.10045.3.1.7", bits: 128 },
  prime256v1: { name: "secp256r1", oid: "1.2.840.10045.3.1.7", bits: 128 },
  secp256r1: { name: "secp256r1", oid: "1.2.840.10045.3.1.7", bits: 128 },
  "p-384": { name: "secp384r1", oid: "1.3.132.0.34", bits: 192 },
  secp384r1: { name: "secp384r1", oid: "1.3.132.0.34", bits: 192 },
  "p-521": { name: "secp521r1", oid: "1.3.132.0.35", bits: 256 },
  secp521r1: { name: "secp521r1", oid: "1.3.132.0.35", bits: 256 },
  secp256k1: { name: "secp256k1", oid: "1.3.132.0.10", bits: 128 },
};

/** SP 800-57 Part 1 Rev. 5 Table 2: classical strength of RSA/DSA moduli it lists. */
const FFC_IFC_STRENGTH: Readonly<Record<string, number>> = { "1024": 80, "2048": 112, "3072": 128, "7680": 192, "15360": 256 };

const OID = {
  rsaEncryption: "1.2.840.113549.1.1.1",
  rsaesOaep: "1.2.840.113549.1.1.7",
  rsassaPss: "1.2.840.113549.1.1.10",
  dsa: "1.2.840.10040.4.1",
  ecPublicKey: "1.2.840.10045.2.1",
  x25519: "1.3.101.110",
  x448: "1.3.101.111",
  ed25519: "1.3.101.112",
  ed448: "1.3.101.113",
  md2: "1.2.840.113549.2.2",
  md4: "1.2.840.113549.2.4",
  md5: "1.2.840.113549.2.5",
  sha1: "1.3.14.3.2.26",
  sha224: "2.16.840.1.101.3.4.2.4",
  sha256: "2.16.840.1.101.3.4.2.1",
  sha384: "2.16.840.1.101.3.4.2.2",
  sha512: "2.16.840.1.101.3.4.2.3",
  hmacSha256: "1.2.840.113549.2.9",
  hmacSha384: "1.2.840.113549.2.10",
  hmacSha512: "1.2.840.113549.2.11",
  desCbc: "1.3.14.3.2.7",
  desEde3Cbc: "1.2.840.113549.3.7",
  rc2Cbc: "1.2.840.113549.3.2",
  rc4: "1.2.840.113549.3.4",
} as const;

/** JOSE algorithm identifiers (RFC 7518) and the X.509 algorithms they are defined as. */
const JOSE: Readonly<Record<string, AlgorithmDescriptor>> = {
  RS256: { primitive: "signature", nistQuantumSecurityLevel: 0, oid: SIGNATURE_OIDS.sha256WithRSAEncryption },
  RS384: { primitive: "signature", nistQuantumSecurityLevel: 0, oid: SIGNATURE_OIDS.sha384WithRSAEncryption },
  RS512: { primitive: "signature", nistQuantumSecurityLevel: 0, oid: SIGNATURE_OIDS.sha512WithRSAEncryption },
  PS256: { primitive: "signature", nistQuantumSecurityLevel: 0, oid: OID.rsassaPss },
  PS384: { primitive: "signature", nistQuantumSecurityLevel: 0, oid: OID.rsassaPss },
  PS512: { primitive: "signature", nistQuantumSecurityLevel: 0, oid: OID.rsassaPss },
  ES256: { primitive: "signature", nistQuantumSecurityLevel: 0, oid: SIGNATURE_OIDS.ecdsaWithSHA256, curve: "secp256r1", classicalSecurityLevel: 128 },
  ES384: { primitive: "signature", nistQuantumSecurityLevel: 0, oid: SIGNATURE_OIDS.ecdsaWithSHA384, curve: "secp384r1", classicalSecurityLevel: 192 },
  ES512: { primitive: "signature", nistQuantumSecurityLevel: 0, oid: SIGNATURE_OIDS.ecdsaWithSHA512, curve: "secp521r1", classicalSecurityLevel: 256 },
  EdDSA: { primitive: "signature", nistQuantumSecurityLevel: 0 },
  // HMAC strength depends on the secret's length, which a JWT algorithm name does not carry.
  HS256: { primitive: "mac", oid: OID.hmacSha256, parameterSetIdentifier: "256" },
  HS384: { primitive: "mac", oid: OID.hmacSha384, parameterSetIdentifier: "384" },
  HS512: { primitive: "mac", oid: OID.hmacSha512, parameterSetIdentifier: "512" },
  none: { primitive: "other", nistQuantumSecurityLevel: 0 },
};

type Rule = readonly [pattern: RegExp, describe: (match: RegExpExecArray, label: string) => AlgorithmDescriptor];

const MODE = /-(cbc|ecb|ccm|gcm|cfb|ofb|ctr)(?:\d*)$/i;

function modeOf(label: string): Mode | undefined {
  return MODE.exec(label)?.[1]?.toLowerCase() as Mode | undefined;
}

function curveOf(name: string | undefined): { name: string; oid: string; bits: number } | undefined {
  return name ? CURVES[name.toLowerCase()] : undefined;
}

/**
 * Canonical-label rules, first match wins. Each row reads the label's own
 * parameters (key size, curve, parameter set), so a level is only stated when
 * the label determines it.
 */
const ALGORITHM_RULES: readonly Rule[] = [
  [/^jwt-(.+)$/i, (m) => JOSE[m[1] ?? ""] ?? { primitive: "unknown" }],
  // Hybrid TLS groups (RFC 10024): the ML-KEM half sets the category.
  [
    /^(x25519|secp256r1|secp384r1)mlkem(512|768|1024)$/i,
    (m) => ({
      primitive: "kem",
      nistQuantumSecurityLevel: ML_KEM[m[2] ?? ""]?.level,
      parameterSetIdentifier: m[2],
      curve: m[1]?.toLowerCase() === "x25519" ? "Curve25519" : m[1]?.toLowerCase(),
    }),
  ],
  [
    /^ml-?kem-?(512|768|1024)?$/i,
    (m) => {
      const set = m[1] ? ML_KEM[m[1]] : undefined;
      return { primitive: "kem", nistQuantumSecurityLevel: set?.level, oid: set?.oid, parameterSetIdentifier: m[1] };
    },
  ],
  [
    /^ml-dsa(?:-(44|65|87))?$/i,
    (m, label) => ({
      primitive: "signature",
      nistQuantumSecurityLevel: m[1] ? ML_DSA_LEVEL[m[1]] : undefined,
      oid: PQ_SIGNATURE_OIDS[label.toUpperCase()],
      parameterSetIdentifier: m[1],
    }),
  ],
  [
    /^slh-dsa(?:-((?:sha2|shake)-(128|192|256)[sf]))?$/i,
    (m, label) => ({
      primitive: "signature",
      nistQuantumSecurityLevel: m[2] ? SLH_DSA_LEVEL[m[2]] : undefined,
      oid: Object.entries(PQ_SIGNATURE_OIDS).find(([name]) => name.toLowerCase() === label.toLowerCase())?.[1],
      parameterSetIdentifier: m[1] ? `${(m[1].split("-")[0] ?? "").toUpperCase()}-${m[1].split("-")[1] ?? ""}` : undefined,
    }),
  ],
  // Signature-algorithm names read from a certificate's ASN.1.
  [
    /^(?:md[245]|sha\d*)withrsaencryption$|^rsassapss$|^(?:dsa|ecdsa)withsha\d*$/i,
    (_m, label) => {
      const oid = Object.entries(SIGNATURE_OIDS).find(([name]) => name.toLowerCase() === label.toLowerCase())?.[1];
      return { primitive: "signature", nistQuantumSecurityLevel: 0, oid };
    },
  ],
  [
    /^rsa-pss(?:-(\d+))?$/i,
    (m) => ({
      primitive: "signature",
      nistQuantumSecurityLevel: 0,
      oid: OID.rsassaPss,
      parameterSetIdentifier: m[1],
      classicalSecurityLevel: m[1] ? FFC_IFC_STRENGTH[m[1]] : undefined,
    }),
  ],
  [/^rsa-?oaep|^rsaes-oaep/i, () => ({ primitive: "pke", nistQuantumSecurityLevel: 0, oid: OID.rsaesOaep })],
  [
    /^rsa(?:-(\d+))?$/i,
    (m) => ({
      primitive: "signature",
      nistQuantumSecurityLevel: 0,
      oid: OID.rsaEncryption,
      parameterSetIdentifier: m[1],
      classicalSecurityLevel: m[1] ? FFC_IFC_STRENGTH[m[1]] : undefined,
    }),
  ],
  [
    /^dsa(?:-(\d+))?$/i,
    (m) => ({
      primitive: "signature",
      nistQuantumSecurityLevel: 0,
      oid: OID.dsa,
      parameterSetIdentifier: m[1],
      classicalSecurityLevel: m[1] ? FFC_IFC_STRENGTH[m[1]] : undefined,
    }),
  ],
  [
    /^(ecdsa|ecdhe?)(?:-(.+))?$/i,
    (m) => {
      const curve = curveOf(m[2]);
      const agree = m[1]?.toLowerCase().startsWith("ecdh") === true;
      return {
        primitive: agree ? "key-agree" : "signature",
        nistQuantumSecurityLevel: 0,
        ...(agree ? {} : { oid: OID.ecPublicKey }),
        curve: curve?.name ?? (m[2] && m[2] !== "unknown-curve" ? m[2] : undefined),
        classicalSecurityLevel: curve?.bits,
      };
    },
  ],
  [/^ed25519$/i, () => ({ primitive: "signature", nistQuantumSecurityLevel: 0, oid: OID.ed25519, curve: "Ed25519", classicalSecurityLevel: 128 })],
  [/^ed448$/i, () => ({ primitive: "signature", nistQuantumSecurityLevel: 0, oid: OID.ed448, curve: "Ed448", classicalSecurityLevel: 224 })],
  [/^x25519$/i, () => ({ primitive: "key-agree", nistQuantumSecurityLevel: 0, oid: OID.x25519, curve: "Curve25519", classicalSecurityLevel: 128 })],
  [/^x448$/i, () => ({ primitive: "key-agree", nistQuantumSecurityLevel: 0, oid: OID.x448, curve: "Curve448", classicalSecurityLevel: 224 })],
  [/^(?:ffdhe\d+|dhe?)$/i, () => ({ primitive: "key-agree", nistQuantumSecurityLevel: 0 })],
  [/^hmac(?:-sha-?(256|384|512))?$/i, (m) => ({ primitive: "mac", parameterSetIdentifier: m[1] })],
  // Hashes: NIST categories 2 and 4 are defined by SHA-256 / SHA-384 collision search.
  [/^md2$/i, () => ({ primitive: "hash", nistQuantumSecurityLevel: 0, oid: OID.md2 })],
  [/^md4$/i, () => ({ primitive: "hash", nistQuantumSecurityLevel: 0, oid: OID.md4 })],
  [/^md5$/i, () => ({ primitive: "hash", nistQuantumSecurityLevel: 0, oid: OID.md5 })],
  [/^sha-?1$/i, () => ({ primitive: "hash", nistQuantumSecurityLevel: 0, oid: OID.sha1 })],
  [/^sha-?224$/i, () => ({ primitive: "hash", oid: OID.sha224, parameterSetIdentifier: "224", classicalSecurityLevel: 112 })],
  [/^sha-?256$/i, () => ({ primitive: "hash", nistQuantumSecurityLevel: 2, oid: OID.sha256, parameterSetIdentifier: "256", classicalSecurityLevel: 128 })],
  [/^sha-?384$/i, () => ({ primitive: "hash", nistQuantumSecurityLevel: 4, oid: OID.sha384, parameterSetIdentifier: "384", classicalSecurityLevel: 192 })],
  [/^sha-?512$/i, () => ({ primitive: "hash", oid: OID.sha512, parameterSetIdentifier: "512", classicalSecurityLevel: 256 })],
  // Symmetric ciphers: AES-128/192/256 define NIST categories 1/3/5.
  [
    /^aes(?:-?(128|192|256))?/i,
    (m, label) => ({
      primitive: /gcm|ccm/i.test(label) ? "ae" : "block-cipher",
      nistQuantumSecurityLevel: m[1] ? { "128": 1, "192": 3, "256": 5 }[m[1]] : undefined,
      parameterSetIdentifier: m[1],
      classicalSecurityLevel: m[1] ? Number(m[1]) : undefined,
      mode: modeOf(label),
    }),
  ],
  [
    /^(?:des-ede3|3des|tripledes|desede)(?:-|$)/i,
    (_m, label) => ({
      primitive: "block-cipher",
      nistQuantumSecurityLevel: 0,
      classicalSecurityLevel: 112,
      oid: /^des-ede3-cbc$/i.test(label) ? OID.desEde3Cbc : undefined,
      mode: modeOf(label),
    }),
  ],
  [
    /^des(?:-|$)/i,
    (_m, label) => ({
      primitive: "block-cipher",
      nistQuantumSecurityLevel: 0,
      classicalSecurityLevel: /^des-ede(?:-|$)/i.test(label) ? 80 : 56,
      oid: /^des-cbc$/i.test(label) ? OID.desCbc : undefined,
      mode: modeOf(label),
    }),
  ],
  [/^rc2(?:-|$)/i, (_m, label) => ({ primitive: "block-cipher", nistQuantumSecurityLevel: 0, oid: /^rc2-cbc$/i.test(label) ? OID.rc2Cbc : undefined, mode: modeOf(label) })],
  [/^(?:rc4|arcfour|arc4)(?:-|$)/i, (_m, label) => ({ primitive: "stream-cipher", nistQuantumSecurityLevel: 0, oid: /^rc4$/i.test(label) ? OID.rc4 : undefined })],
  [/^(?:chacha20-poly1305|xsalsa20-poly1305)$/i, () => ({ primitive: "ae" })],
];

/** Drop undefined fields, so the JSON never carries `"oid": undefined` noise and equality checks stay simple. */
function compact<T extends object>(value: T): T {
  return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined)) as T;
}

/**
 * Classify a canonical algorithm label into CycloneDX crypto vocabulary.
 * `usage` refines primitives the label alone leaves open: an RSA key used for
 * encryption is `pke`, not `signature`.
 */
export function describeAlgorithm(label: string, usage: readonly CryptoUsage[] = []): AlgorithmDescriptor {
  for (const [pattern, describe] of ALGORITHM_RULES) {
    const match = pattern.exec(label);
    if (!match) continue;
    const descriptor = describe(match, label);
    const encryptionOnly = usage.includes("encryption") && !usage.includes("signature") && !usage.includes("authentication");
    if (encryptionOnly && descriptor.primitive === "signature" && /^rsa(?:-\d+)?$/i.test(label)) {
      return compact({ ...descriptor, primitive: "pke" });
    }
    return compact(descriptor);
  }
  return { primitive: "unknown" };
}

/** CycloneDX 1.6 `cryptoProperties.assetType` values we emit. */
type AssetType = "algorithm" | "certificate" | "related-crypto-material" | "protocol";

interface Occurrence {
  location: string;
  line?: number;
}

interface Property {
  name: string;
  value: string;
}

interface CryptoProperties {
  assetType: AssetType;
  algorithmProperties?: Omit<AlgorithmDescriptor, "oid">;
  certificateProperties?: {
    subjectName?: string;
    issuerName?: string;
    notValidBefore?: string;
    notValidAfter?: string;
    signatureAlgorithmRef?: string;
    subjectPublicKeyRef?: string;
    certificateFormat: string;
  };
  relatedCryptoMaterialProperties?: {
    type: "private-key" | "public-key";
    state?: "compromised";
    algorithmRef?: string;
    size?: number;
  };
  protocolProperties?: {
    type: "tls" | "ssh" | "ipsec" | "ike" | "sstp" | "wpa" | "other" | "unknown";
    version?: string;
    cipherSuites?: { name: string }[];
    cryptoRefArray?: string[];
  };
  oid?: string;
}

interface CryptoComponent {
  type: "cryptographic-asset";
  "bom-ref": string;
  name: string;
  cryptoProperties: CryptoProperties;
  evidence?: { occurrences: Occurrence[] };
  properties: Property[];
}

interface LibraryComponent {
  type: "library";
  "bom-ref": string;
  name: string;
  version?: string;
  purl: string;
  evidence?: { occurrences: Occurrence[] };
  properties: Property[];
}

interface Dependency {
  ref: string;
  dependsOn?: string[];
  provides?: string[];
}

const PQ_RANK: Record<PqStatus, number> = { vulnerable: 0, transitional: 1, unknown: 2, safe: 3 };
const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/**
 * Accumulates the BOM. Every asset is keyed by its bom-ref, so a second
 * finding about the same asset adds an occurrence and a finding id instead of a
 * duplicate component.
 */
class BomBuilder {
  private readonly crypto = new Map<string, { component: CryptoComponent; findings: Finding[] }>();
  private readonly libraries = new Map<string, { component: LibraryComponent; provides: Set<string>; findings: Finding[] }>();
  /** Algorithm assets whose OID a scanner read, which a catalogue OID must never replace. */
  private readonly scannerOids = new Set<string>();

  /**
   * Add (or extend) an algorithm asset and return its bom-ref. An OID the
   * scanner read from the artifact (`oid`) wins over the catalogue's.
   */
  algorithm(label: string, usage: readonly CryptoUsage[], oid: string | undefined, finding?: Finding): string {
    const ref = `crypto/algorithm/${slug(label)}`;
    const existing = this.crypto.get(ref);
    if (existing) {
      if (finding) existing.findings.push(finding);
      if (oid && !this.scannerOids.has(ref)) {
        existing.component.cryptoProperties.oid = oid;
        this.scannerOids.add(ref);
      }
      return ref;
    }
    const { oid: catalogOid, ...algorithmProperties } = describeAlgorithm(label, usage);
    const resolvedOid = oid ?? catalogOid;
    if (oid) this.scannerOids.add(ref);
    this.crypto.set(ref, {
      component: {
        type: "cryptographic-asset",
        "bom-ref": ref,
        name: sanitizeText(label),
        cryptoProperties: { assetType: "algorithm", algorithmProperties, ...(resolvedOid ? { oid: resolvedOid } : {}) },
        properties: [],
      },
      findings: finding ? [finding] : [],
    });
    return ref;
  }

  /**
   * Add (or extend) a non-algorithm asset under a caller-chosen bom-ref. The
   * display name is built from file paths and certificate subjects, so it is
   * sanitized like every other display string.
   */
  asset(ref: string, name: string, cryptoProperties: CryptoProperties, finding: Finding): string {
    const existing = this.crypto.get(ref);
    if (existing) {
      existing.findings.push(finding);
      return ref;
    }
    this.crypto.set(ref, {
      component: { type: "cryptographic-asset", "bom-ref": ref, name: sanitizeText(name), cryptoProperties, properties: [] },
      findings: [finding],
    });
    return ref;
  }

  library(component: Omit<LibraryComponent, "evidence">, finding: Finding, provides: readonly string[]): void {
    const existing = this.libraries.get(component["bom-ref"]);
    if (existing) {
      existing.findings.push(finding);
      for (const ref of provides) existing.provides.add(ref);
      for (const property of component.properties) {
        const duplicate = existing.component.properties.some((p) => p.name === property.name && p.value === property.value);
        if (!duplicate) existing.component.properties.push(property);
      }
      return;
    }
    this.libraries.set(component["bom-ref"], {
      component: { ...component, properties: [...component.properties] },
      provides: new Set(provides),
      findings: [finding],
    });
  }

  components(): Array<CryptoComponent | LibraryComponent> {
    const cryptoAssets = [...this.crypto.values()].map(({ component, findings }) => withProvenance(component, findings));
    const libraries = [...this.libraries.values()].map(({ component, findings }) => withProvenance(component, findings));
    return [...libraries, ...cryptoAssets];
  }

  dependencies(rootRef: string): Dependency[] {
    const libraryRefs = [...this.libraries.keys()];
    const out: Dependency[] = [];
    if (libraryRefs.length > 0) out.push({ ref: rootRef, dependsOn: libraryRefs });
    for (const [ref, { provides }] of this.libraries) {
      if (provides.size > 0) out.push({ ref, provides: [...provides] });
    }
    return out;
  }
}

/** Attach occurrences and the cryptosweep properties (worst posture, finding ids) derived from the findings. */
function withProvenance<T extends CryptoComponent | LibraryComponent>(component: T, findings: readonly Finding[]): T {
  if (findings.length === 0) return component;
  const worstPq = findings.reduce((a, f) => (PQ_RANK[f.pq_status] < PQ_RANK[a] ? f.pq_status : a), "safe" as PqStatus);
  const worstSeverity = findings.reduce((a, f) => (SEVERITY_RANK[f.severity] < SEVERITY_RANK[a] ? f.severity : a), "info" as Severity);
  const properties: Property[] = [
    ...component.properties,
    { name: "cryptosweep:pq_status", value: worstPq },
    { name: "cryptosweep:severity", value: worstSeverity },
    ...unique(findings.map((f) => f.confidence ?? "medium")).map((value) => ({ name: "cryptosweep:confidence", value })),
    ...unique(findings.map((f) => f.id)).map((value) => ({ name: "cryptosweep:finding", value })),
  ];
  const occurrences = uniqueBy(findings.map(occurrenceOf).filter((o): o is Occurrence => o !== null), (o) => `${o.location}#${o.line ?? ""}`);
  return { ...component, properties, ...(occurrences.length > 0 ? { evidence: { occurrences } } : {}) };
}

function occurrenceOf(finding: Finding): Occurrence | null {
  const { path, line, host, port } = finding.location ?? {};
  if (path) return line ? { location: path, line } : { location: path };
  if (host) return { location: endpointOf(host, port) };
  return null;
}

function endpointOf(host: string, port: number | undefined): string {
  const authority = host.includes(":") ? `[${host}]` : host;
  return `tls://${port ? `${authority}:${port}` : authority}`;
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)];
}

function uniqueBy<T>(values: readonly T[], key: (value: T) => string): T[] {
  const seen = new Map<string, T>();
  for (const value of values) if (!seen.has(key(value))) seen.set(key(value), value);
  return [...seen.values()];
}

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "asset";
}

/** A stable short digest, for bom-refs of assets that have no natural short name. */
function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}

/** True for an RFC 3339 date-time, the only form CycloneDX accepts in certificate validity fields. */
function isDateTime(value: string): boolean {
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value) && !Number.isNaN(Date.parse(value));
}

/** One certificate asset, linked to its signature algorithm and to a public-key asset for its subject key. */
function addCertificate(bom: BomBuilder, cert: CertificateDetails, finding: Finding): void {
  const identity = `${cert.subject}|${cert.issuer}|${cert.notValidAfter}|${cert.publicKey}`;
  const signatureRef = bom.algorithm(cert.signatureAlgorithm, ["signature"], cert.signatureOid, finding);
  const keyAlgorithmRef = bom.algorithm(cert.publicKey, ["signature"], undefined, finding);
  const keyRef = bom.asset(
    `crypto/key/public/${digest(identity)}`,
    `${cert.subject} public key`,
    {
      assetType: "related-crypto-material",
      relatedCryptoMaterialProperties: {
        type: "public-key",
        algorithmRef: keyAlgorithmRef,
        ...(cert.publicKeyBits ? { size: cert.publicKeyBits } : {}),
      },
    },
    finding,
  );
  bom.asset(
    `crypto/certificate/${digest(identity)}`,
    cert.subject,
    {
      assetType: "certificate",
      certificateProperties: {
        subjectName: cert.subject,
        issuerName: cert.issuer,
        ...(isDateTime(cert.notValidBefore) ? { notValidBefore: cert.notValidBefore } : {}),
        ...(isDateTime(cert.notValidAfter) ? { notValidAfter: cert.notValidAfter } : {}),
        signatureAlgorithmRef: signatureRef,
        subjectPublicKeyRef: keyRef,
        certificateFormat: "X.509",
      },
    },
    finding,
  );
}

/**
 * Without parsed certificate details, the leaf's signature algorithm and key
 * still come from structured fields (`ruleId` + `algorithm` + endpoint), so the
 * leaf is inventoried with the links it can honestly carry and nothing more.
 */
function addLeafFromFindings(bom: BomBuilder, findings: readonly Finding[]): void {
  const byEndpoint = new Map<string, { signature?: Finding; key?: Finding }>();
  for (const f of findings) {
    if (f.certificates?.length || !f.algorithm || !f.location?.host) continue;
    if (f.ruleId !== "tls/leaf-signature" && f.ruleId !== "tls/leaf-public-key") continue;
    const endpoint = endpointOf(f.location.host, f.location.port);
    const entry = byEndpoint.get(endpoint) ?? {};
    if (f.ruleId === "tls/leaf-signature") entry.signature = f;
    else entry.key = f;
    byEndpoint.set(endpoint, entry);
  }
  for (const [endpoint, { signature, key }] of byEndpoint) {
    const anchor = signature ?? key;
    if (!anchor) continue;
    const signatureRef = signature?.algorithm ? bom.algorithm(signature.algorithm, ["signature"], signature.oid) : undefined;
    const keyRef =
      key?.algorithm
        ? bom.asset(
            `crypto/key/public/${digest(`leaf|${endpoint}`)}`,
            `Leaf public key (${endpoint})`,
            {
              assetType: "related-crypto-material",
              relatedCryptoMaterialProperties: {
                type: "public-key",
                algorithmRef: bom.algorithm(key.algorithm, ["signature"], key.oid),
              },
            },
            key,
          )
        : undefined;
    bom.asset(
      `crypto/certificate/${digest(`leaf|${endpoint}`)}`,
      `Leaf certificate (${endpoint})`,
      {
        assetType: "certificate",
        certificateProperties: {
          ...(signatureRef ? { signatureAlgorithmRef: signatureRef } : {}),
          ...(keyRef ? { subjectPublicKeyRef: keyRef } : {}),
          certificateFormat: "X.509",
        },
      },
      anchor,
    );
  }
}

const PROTOCOL_TYPES = new Set(["tls", "ssh", "ipsec", "ike", "sstp", "wpa"]);

function addProtocol(bom: BomBuilder, finding: Finding): void {
  const details = finding.protocol;
  const type = details?.type.toLowerCase() ?? "tls";
  const protocolType = (PROTOCOL_TYPES.has(type) ? type : "other") as NonNullable<CryptoProperties["protocolProperties"]>["type"];
  const endpoint = finding.location?.host ? endpointOf(finding.location.host, finding.location.port) : finding.evidence;
  const groupRef = details?.group ? bom.algorithm(details.group, ["key-establishment"], undefined, finding) : undefined;
  const name = details?.version ? `${protocolType.toUpperCase()} ${details.version}` : protocolType.toUpperCase();
  bom.asset(
    `crypto/protocol/${slug(`${protocolType}-${details?.version ?? "unknown"}`)}-${digest(endpoint)}`,
    `${name} (${endpoint})`,
    {
      assetType: "protocol",
      protocolProperties: {
        type: protocolType,
        ...(details?.version ? { version: details.version } : {}),
        ...(details?.cipherSuite ? { cipherSuites: [{ name: details.cipherSuite }] } : {}),
        ...(groupRef ? { cryptoRefArray: [groupRef] } : {}),
      },
    },
    finding,
  );
}

/** Key material from a `keys` finding, one asset per occurrence (each is a distinct key). */
function addKeyMaterial(bom: BomBuilder, finding: Finding, usage: readonly CryptoUsage[]): void {
  const isPrivate = usage.includes("secret-material");
  const where = occurrenceOf(finding);
  const place = where ? `${where.location}${where.line ? `:${where.line}` : ""}` : finding.id;
  const algorithmRef = finding.algorithm ? bom.algorithm(finding.algorithm, usage, finding.oid, finding) : undefined;
  bom.asset(
    `crypto/key/${isPrivate ? "private" : "public"}/${digest(`${finding.ruleId ?? ""}|${place}`)}`,
    `${isPrivate ? "Private" : "Public"} key material (${place})`,
    {
      assetType: "related-crypto-material",
      relatedCryptoMaterialProperties: {
        type: isPrivate ? "private-key" : "public-key",
        // Key material disclosed in a repository is compromised by definition (SP 800-57 Part 1).
        ...(isPrivate ? { state: "compromised" as const } : {}),
        ...(algorithmRef ? { algorithmRef } : {}),
      },
    },
    finding,
  );
}

/** The purl type for each ecosystem the registry covers (purl-spec). */
const PURL_TYPE: Readonly<Record<string, string>> = { npm: "npm", python: "pypi", cargo: "cargo" };

/** A concrete version (not a range), which is all CycloneDX `version` and a purl may carry. */
function pinnedVersion(version: string | undefined): string | undefined {
  const v = (version ?? "").trim().replace(/^==?/, "");
  return /^\d+(?:\.\d+)*(?:[-+.][0-9A-Za-z.-]+)?$/.test(v) ? v : undefined;
}

function purlOf(ecosystem: string, name: string, version: string | undefined): string {
  const type = PURL_TYPE[ecosystem] ?? ecosystem;
  // PyPI names are case-insensitive with `_` equivalent to `-` (purl-spec, PEP 503).
  const normalized = type === "pypi" ? name.toLowerCase().replace(/[-_.]+/g, "-") : name;
  const path = normalized
    .split("/")
    .map((part) => encodeURIComponent(part))
    .join("/");
  return `pkg:${type}/${path}${version ? `@${encodeURIComponent(version)}` : ""}`;
}

function addLibrary(bom: BomBuilder, finding: Finding): void {
  const entry = entryForRuleId(finding.ruleId);
  const ecosystem = finding.dependency?.ecosystem ?? entry?.ecosystem;
  const name = finding.dependency?.name ?? entry?.name;
  if (!ecosystem || !name) return;
  const declared = finding.dependency?.version;
  const version = pinnedVersion(declared);
  const purl = purlOf(ecosystem, name, version);
  const provides = (entry?.algorithms ?? []).map((label) => bom.algorithm(label, entry?.usage ?? [], undefined));
  // A range is not a version: keep what the manifest said without pretending it is one.
  const properties = declared && !version ? [{ name: "cryptosweep:declared-version", value: declared }] : [];
  bom.library({ type: "library", "bom-ref": purl, name, ...(version ? { version } : {}), purl, properties }, finding, provides);
}

/** Route each finding to the asset(s) it evidences. */
function buildBom(findings: readonly Finding[]): BomBuilder {
  const bom = new BomBuilder();
  for (const finding of findings) {
    const usage = resolveUsage(finding);
    if (finding.category === "deps") {
      addLibrary(bom, finding);
      continue;
    }
    if (finding.certificates?.length) {
      for (const cert of finding.certificates) addCertificate(bom, cert, finding);
      continue;
    }
    if (finding.category === "keys") {
      addKeyMaterial(bom, finding, usage);
      continue;
    }
    if (finding.protocol || finding.ruleId === "tls/negotiated-protocol") {
      addProtocol(bom, finding);
      if (!finding.algorithm) continue;
    }
    if (finding.algorithm) bom.algorithm(finding.algorithm, usage, finding.oid, finding);
  }
  addLeafFromFindings(bom, findings);
  return bom;
}

/** Deterministic BOM serial number derived from the report, so output is reproducible. */
function serialNumber(report: Report): string {
  const hex = createHash("sha256").update(`${report.target}|${report.scanned_at}`).digest("hex");
  const uuid = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-8${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
  return `urn:uuid:${uuid}`;
}

/** Render a report as a CycloneDX 1.6 CBOM document (pretty JSON). */
export function toCbom(report: Report): string {
  const bom = buildBom(report.findings);
  const rootRef = "target";
  const dependencies = bom.dependencies(rootRef);
  const document = {
    $schema: "http://cyclonedx.org/schema/bom-1.6.schema.json",
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: serialNumber(report),
    version: 1,
    metadata: {
      timestamp: report.scanned_at,
      tools: {
        components: [
          {
            type: "application",
            name: "cryptosweep",
            version: VERSION,
            "bom-ref": "tool/cryptosweep",
            externalReferences: [{ type: "vcs", url: REPOSITORY_URL }],
          },
        ],
      },
      component: {
        type: "application",
        "bom-ref": rootRef,
        name: report.target,
      },
    },
    components: bom.components(),
    ...(dependencies.length > 0 ? { dependencies } : {}),
  };
  return JSON.stringify(document, null, 2);
}
