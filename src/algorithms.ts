/**
 * The algorithm-label vocabulary, shared by every consumer of `Finding.algorithm`.
 *
 * Scanners name primitives with canonical labels (`RSA-2048`, `ECDSA-P-256`,
 * `rsassaPss-sha256`, `DHE-1024`, `X25519MLKEM768`, `JWT-ES256K`, ...). This
 * module is the one place that reads a label back: the CBOM types it with the
 * CycloneDX primitive vocabulary, its OID and NIST quantum security level, and
 * the risk engine derives a label's use from the same row. A label the table
 * does not know is `unknown` in both, and `tests/algorithm-vocabulary.test.ts`
 * runs every label the scanners can emit through it, so a scanner that starts
 * emitting a new spelling fails the build instead of shipping `unknown`.
 */
import type { CryptoUsage } from "./report";

/** CycloneDX 1.6 `algorithmProperties.primitive` values. */
export type Primitive =
  | "signature"
  | "kem"
  | "key-agree"
  | "pke"
  | "hash"
  | "xof"
  | "kdf"
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
  "HashML-DSA-44": "2.16.840.1.101.3.4.3.32",
  "HashML-DSA-65": "2.16.840.1.101.3.4.3.33",
  "HashML-DSA-87": "2.16.840.1.101.3.4.3.34",
  "HashSLH-DSA-SHA2-128s": "2.16.840.1.101.3.4.3.35",
  "HashSLH-DSA-SHA2-128f": "2.16.840.1.101.3.4.3.36",
  "HashSLH-DSA-SHA2-192s": "2.16.840.1.101.3.4.3.37",
  "HashSLH-DSA-SHA2-192f": "2.16.840.1.101.3.4.3.38",
  "HashSLH-DSA-SHA2-256s": "2.16.840.1.101.3.4.3.39",
  "HashSLH-DSA-SHA2-256f": "2.16.840.1.101.3.4.3.40",
  "HashSLH-DSA-SHAKE-128s": "2.16.840.1.101.3.4.3.41",
  "HashSLH-DSA-SHAKE-128f": "2.16.840.1.101.3.4.3.42",
  "HashSLH-DSA-SHAKE-192s": "2.16.840.1.101.3.4.3.43",
  "HashSLH-DSA-SHAKE-192f": "2.16.840.1.101.3.4.3.44",
  "HashSLH-DSA-SHAKE-256s": "2.16.840.1.101.3.4.3.45",
  "HashSLH-DSA-SHAKE-256f": "2.16.840.1.101.3.4.3.46",
};

/** Stateful hash-based signatures (NIST SP 800-208): one OID names the key and the signature (RFC 9708, RFC 9802). */
const STATEFUL_HASH_OIDS: Readonly<Record<string, string>> = {
  "hss-lms": "1.2.840.113549.1.9.16.3.17",
  lms: "1.2.840.113549.1.9.16.3.17",
  xmss: "1.3.6.1.5.5.7.6.34",
  xmssmt: "1.3.6.1.5.5.7.6.35",
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

/** Curves by the friendly and OpenSSL names the scanners emit: SECG name, curve OID, classical strength (SP 800-57). */
const CURVES: Readonly<Record<string, { name: string; oid: string; bits: number }>> = {
  "p-192": { name: "secp192r1", oid: "1.2.840.10045.3.1.1", bits: 80 },
  prime192v1: { name: "secp192r1", oid: "1.2.840.10045.3.1.1", bits: 80 },
  secp192r1: { name: "secp192r1", oid: "1.2.840.10045.3.1.1", bits: 80 },
  secp192k1: { name: "secp192k1", oid: "1.3.132.0.31", bits: 80 },
  "p-224": { name: "secp224r1", oid: "1.3.132.0.33", bits: 112 },
  secp224r1: { name: "secp224r1", oid: "1.3.132.0.33", bits: 112 },
  "p-256": { name: "secp256r1", oid: "1.2.840.10045.3.1.7", bits: 128 },
  prime256v1: { name: "secp256r1", oid: "1.2.840.10045.3.1.7", bits: 128 },
  secp256r1: { name: "secp256r1", oid: "1.2.840.10045.3.1.7", bits: 128 },
  "p-384": { name: "secp384r1", oid: "1.3.132.0.34", bits: 192 },
  secp384r1: { name: "secp384r1", oid: "1.3.132.0.34", bits: 192 },
  "p-521": { name: "secp521r1", oid: "1.3.132.0.35", bits: 256 },
  secp521r1: { name: "secp521r1", oid: "1.3.132.0.35", bits: 256 },
  secp256k1: { name: "secp256k1", oid: "1.3.132.0.10", bits: 128 },
  brainpoolp256r1: { name: "brainpoolP256r1", oid: "1.3.36.3.3.2.8.1.1.7", bits: 128 },
  brainpoolp384r1: { name: "brainpoolP384r1", oid: "1.3.36.3.3.2.8.1.1.11", bits: 192 },
  brainpoolp512r1: { name: "brainpoolP512r1", oid: "1.3.36.3.3.2.8.1.1.13", bits: 256 },
  // Montgomery curves, as a TLS group name puts them after "ECDHE-".
  x25519: { name: "Curve25519", oid: "1.3.101.110", bits: 128 },
  x448: { name: "Curve448", oid: "1.3.101.111", bits: 224 },
};

/** SP 800-57 Part 1 Rev. 5 Table 2: classical strength of the RSA/DSA/DH moduli it lists. */
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
  sha3_224: "2.16.840.1.101.3.4.2.7",
  sha3_256: "2.16.840.1.101.3.4.2.8",
  sha3_384: "2.16.840.1.101.3.4.2.9",
  sha3_512: "2.16.840.1.101.3.4.2.10",
  ripemd160: "1.3.36.3.2.1",
  hmacMd5: "1.3.6.1.5.5.8.1.1",
  hmacSha1: "1.2.840.113549.2.7",
  hmacSha224: "1.2.840.113549.2.8",
  hmacSha256: "1.2.840.113549.2.9",
  hmacSha384: "1.2.840.113549.2.10",
  hmacSha512: "1.2.840.113549.2.11",
  pbkdf2: "1.2.840.113549.1.5.12",
  desCbc: "1.3.14.3.2.7",
  desEde3Cbc: "1.2.840.113549.3.7",
  rc2Cbc: "1.2.840.113549.3.2",
  rc4: "1.2.840.113549.3.4",
} as const;

const HMAC_OIDS: Readonly<Record<string, string>> = {
  md5: OID.hmacMd5,
  sha1: OID.hmacSha1,
  sha224: OID.hmacSha224,
  sha256: OID.hmacSha256,
  sha384: OID.hmacSha384,
  sha512: OID.hmacSha512,
};

/** JOSE algorithm identifiers (RFC 7518, RFC 8037, RFC 8812) and the X.509 algorithms they are defined as. */
const JOSE: Readonly<Record<string, AlgorithmDescriptor>> = {
  RS256: { primitive: "signature", nistQuantumSecurityLevel: 0, oid: SIGNATURE_OIDS.sha256WithRSAEncryption },
  RS384: { primitive: "signature", nistQuantumSecurityLevel: 0, oid: SIGNATURE_OIDS.sha384WithRSAEncryption },
  RS512: { primitive: "signature", nistQuantumSecurityLevel: 0, oid: SIGNATURE_OIDS.sha512WithRSAEncryption },
  PS256: { primitive: "signature", nistQuantumSecurityLevel: 0, oid: OID.rsassaPss },
  PS384: { primitive: "signature", nistQuantumSecurityLevel: 0, oid: OID.rsassaPss },
  PS512: { primitive: "signature", nistQuantumSecurityLevel: 0, oid: OID.rsassaPss },
  ES256: { primitive: "signature", nistQuantumSecurityLevel: 0, oid: SIGNATURE_OIDS.ecdsaWithSHA256, curve: "secp256r1", classicalSecurityLevel: 128 },
  ES256K: { primitive: "signature", nistQuantumSecurityLevel: 0, oid: SIGNATURE_OIDS.ecdsaWithSHA256, curve: "secp256k1", classicalSecurityLevel: 128 },
  ES384: { primitive: "signature", nistQuantumSecurityLevel: 0, oid: SIGNATURE_OIDS.ecdsaWithSHA384, curve: "secp384r1", classicalSecurityLevel: 192 },
  ES512: { primitive: "signature", nistQuantumSecurityLevel: 0, oid: SIGNATURE_OIDS.ecdsaWithSHA512, curve: "secp521r1", classicalSecurityLevel: 256 },
  EdDSA: { primitive: "signature", nistQuantumSecurityLevel: 0 },
  Ed25519: { primitive: "signature", nistQuantumSecurityLevel: 0, oid: OID.ed25519, curve: "Ed25519", classicalSecurityLevel: 128 },
  Ed448: { primitive: "signature", nistQuantumSecurityLevel: 0, oid: OID.ed448, curve: "Ed448", classicalSecurityLevel: 224 },
  // HMAC strength depends on the secret's length, which a JWT algorithm name does not carry.
  HS256: { primitive: "mac", oid: OID.hmacSha256, parameterSetIdentifier: "256" },
  HS384: { primitive: "mac", oid: OID.hmacSha384, parameterSetIdentifier: "384" },
  HS512: { primitive: "mac", oid: OID.hmacSha512, parameterSetIdentifier: "512" },
  // JWE key management: RSA key transport and ECDH-ES key agreement.
  RSA1_5: { primitive: "pke", nistQuantumSecurityLevel: 0, oid: OID.rsaEncryption },
  none: { primitive: "other", nistQuantumSecurityLevel: 0 },
};

function joseDescriptor(alg: string): AlgorithmDescriptor {
  const exact = JOSE[alg];
  if (exact) return exact;
  if (/^RSA-OAEP(?:-(?:256|384|512))?$/.test(alg)) return { primitive: "pke", nistQuantumSecurityLevel: 0, oid: OID.rsaesOaep };
  if (/^ECDH-ES(?:\+A(?:128|192|256)KW)?$/.test(alg)) return { primitive: "key-agree", nistQuantumSecurityLevel: 0 };
  return { primitive: "unknown" };
}

type Rule = readonly [pattern: RegExp, describe: (match: RegExpExecArray, label: string) => AlgorithmDescriptor];

const MODE = /-(cbc|ecb|ccm|gcm|cfb|ofb|ctr)(?:\d*)$/i;

function modeOf(label: string): Mode | undefined {
  return MODE.exec(label)?.[1]?.toLowerCase() as Mode | undefined;
}

function curveOf(name: string | undefined): { name: string; oid: string; bits: number } | undefined {
  return name ? CURVES[name.toLowerCase()] : undefined;
}

/** RSA / RSA-PSS / DSA keys: the size is the parameter set and sets the SP 800-57 strength. */
function integerKey(oid: string): (match: RegExpExecArray) => AlgorithmDescriptor {
  return (m) => ({
    primitive: "signature",
    nistQuantumSecurityLevel: 0,
    oid,
    parameterSetIdentifier: m[1],
    classicalSecurityLevel: m[1] ? FFC_IFC_STRENGTH[m[1]] : undefined,
  });
}

/** `SHA2` / `SHAKE` with the FIPS 205 case convention for the parameter set, e.g. `SHA2-128s`. */
function slhDsaSet(family: string | undefined, size: string | undefined, variant: string | undefined): string | undefined {
  return family && size && variant ? `${family.toUpperCase()}-${size}${variant.toLowerCase()}` : undefined;
}

/**
 * Canonical-label rules, first match wins. Each row reads the label's own
 * parameters (key size, curve, parameter set), so a level is only stated when
 * the label determines it. `RSA-?` / `DSA-?` are the scanners' labels for a
 * key whose size could not be read.
 */
const ALGORITHM_RULES: readonly Rule[] = [
  [/^jwt-(.+)$/i, (m) => joseDescriptor(m[1] ?? "")],
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
  // Pre-standard Kyber hybrids (X25519Kyber768Draft00): a KEM, but not FIPS 203, so no category.
  [/kyber/i, () => ({ primitive: "kem" })],
  [
    /^(hash)?ml-dsa(?:-(44|65|87))?(?:-with-sha512)?$/i,
    (m) => ({
      primitive: "signature",
      nistQuantumSecurityLevel: m[2] ? ML_DSA_LEVEL[m[2]] : undefined,
      oid: m[2] ? PQ_SIGNATURE_OIDS[`${m[1] ? "HashML-DSA" : "ML-DSA"}-${m[2]}`] : undefined,
      parameterSetIdentifier: m[2],
    }),
  ],
  [
    /^(hash)?slh-dsa(?:-(sha2|shake)-(128|192|256)([sf]))?(?:-with-(?:sha256|sha512|shake128|shake256))?$/i,
    (m) => {
      const set = slhDsaSet(m[2], m[3], m[4]);
      return {
        primitive: "signature",
        nistQuantumSecurityLevel: m[3] ? SLH_DSA_LEVEL[m[3]] : undefined,
        oid: set ? PQ_SIGNATURE_OIDS[`${m[1] ? "HashSLH-DSA" : "SLH-DSA"}-${set}`] : undefined,
        parameterSetIdentifier: set,
      };
    },
  ],
  // Stateful hash-based signatures: the level depends on the hash and tree parameters, which the name does not carry.
  [/^(?:hss-lms|lms|xmss|xmssmt)$/i, (_m, label) => ({ primitive: "signature", oid: STATEFUL_HASH_OIDS[label.toLowerCase()] })],
  // Signature-algorithm names read from a certificate's ASN.1.
  [
    /^(?:md[245]|sha\d*)withrsaencryption$|^(?:dsa|ecdsa)withsha\d*$/i,
    (_m, label) => {
      const oid = Object.entries(SIGNATURE_OIDS).find(([name]) => name.toLowerCase() === label.toLowerCase())?.[1];
      return { primitive: "signature", nistQuantumSecurityLevel: 0, oid };
    },
  ],
  // RSASSA-PSS as the TLS scanner names it, with the digest read from its parameters (`rsassaPss-sha256`).
  [/^rsassa-?pss(?:-[a-z0-9-]+)?$/i, () => ({ primitive: "signature", nistQuantumSecurityLevel: 0, oid: OID.rsassaPss })],
  [/^rsa-pss(?:-(\d+)|-\?)?$/i, integerKey(OID.rsassaPss)],
  [/^rsa-?oaep|^rsaes-oaep/i, () => ({ primitive: "pke", nistQuantumSecurityLevel: 0, oid: OID.rsaesOaep })],
  // TLS 1.2 static RSA key transport: the server's RSA key decrypts the premaster secret.
  [/^static-rsa-key-exchange$/i, () => ({ primitive: "pke", nistQuantumSecurityLevel: 0, oid: OID.rsaEncryption })],
  [/^rsa(?:-(\d+)|-\?)?$/i, integerKey(OID.rsaEncryption)],
  [/^dsa(?:-(\d+)|-\?)?$/i, integerKey(OID.dsa)],
  // A signature whose key type the call site leaves open (`createSign` without a key, PyCryptodome DSS).
  [/^(?:rsa|dsa|ecdsa)(?:\/(?:rsa|dsa|ecdsa))+$/i, () => ({ primitive: "signature", nistQuantumSecurityLevel: 0 })],
  // A bare elliptic-curve key of unread curve; `usage` refines it to key agreement.
  [/^ec$/i, () => ({ primitive: "signature", nistQuantumSecurityLevel: 0, oid: OID.ecPublicKey })],
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
  [/^eddsa$/i, () => ({ primitive: "signature", nistQuantumSecurityLevel: 0 })],
  [/^x25519$/i, () => ({ primitive: "key-agree", nistQuantumSecurityLevel: 0, oid: OID.x25519, curve: "Curve25519", classicalSecurityLevel: 128 })],
  [/^x448$/i, () => ({ primitive: "key-agree", nistQuantumSecurityLevel: 0, oid: OID.x448, curve: "Curve448", classicalSecurityLevel: 224 })],
  // Finite-field Diffie-Hellman: `DH`, `DH-2048`, `DHE-1024`, `ffdhe2048` (RFC 7919), `FFDHE-3072`.
  [
    /^(?:ffdhe|dhe?)(?:-?(\d{3,5}))?$/i,
    (m) => ({
      primitive: "key-agree",
      nistQuantumSecurityLevel: 0,
      parameterSetIdentifier: m[1],
      classicalSecurityLevel: m[1] ? FFC_IFC_STRENGTH[m[1]] : undefined,
    }),
  ],
  [/^(?:ecies|elgamal)$/i, () => ({ primitive: "pke", nistQuantumSecurityLevel: 0 })],
  [
    /^hmac(?:-(md5|sha-?1|sha-?(?:224|256|384|512)))?$/i,
    (m) => {
      const digest = m[1]?.toLowerCase().replace("-", "");
      const size = /^sha(224|256|384|512)$/.exec(digest ?? "")?.[1];
      return { primitive: "mac", oid: digest ? HMAC_OIDS[digest] : undefined, parameterSetIdentifier: size };
    },
  ],
  [/^(pbkdf2|hkdf)(?:-(?:md5|sha-?\d+))?$/i, (m) => ({ primitive: "kdf", oid: m[1]?.toLowerCase() === "pbkdf2" ? OID.pbkdf2 : undefined })],
  // Hashes: NIST categories 2 and 4 are defined by SHA-256 / SHA-384 (or SHA3) collision search.
  [/^md2$/i, () => ({ primitive: "hash", nistQuantumSecurityLevel: 0, oid: OID.md2 })],
  [/^md4$/i, () => ({ primitive: "hash", nistQuantumSecurityLevel: 0, oid: OID.md4 })],
  [/^md5$/i, () => ({ primitive: "hash", nistQuantumSecurityLevel: 0, oid: OID.md5 })],
  [/^sha-?1$/i, () => ({ primitive: "hash", nistQuantumSecurityLevel: 0, oid: OID.sha1 })],
  [/^sha-?224$/i, () => ({ primitive: "hash", oid: OID.sha224, parameterSetIdentifier: "224", classicalSecurityLevel: 112 })],
  [/^sha-?256$/i, () => ({ primitive: "hash", nistQuantumSecurityLevel: 2, oid: OID.sha256, parameterSetIdentifier: "256", classicalSecurityLevel: 128 })],
  [/^sha-?384$/i, () => ({ primitive: "hash", nistQuantumSecurityLevel: 4, oid: OID.sha384, parameterSetIdentifier: "384", classicalSecurityLevel: 192 })],
  [/^sha-?512$/i, () => ({ primitive: "hash", oid: OID.sha512, parameterSetIdentifier: "512", classicalSecurityLevel: 256 })],
  [/^sha3-224$/i, () => ({ primitive: "hash", oid: OID.sha3_224, parameterSetIdentifier: "224", classicalSecurityLevel: 112 })],
  [/^sha3-256$/i, () => ({ primitive: "hash", nistQuantumSecurityLevel: 2, oid: OID.sha3_256, parameterSetIdentifier: "256", classicalSecurityLevel: 128 })],
  [/^sha3-384$/i, () => ({ primitive: "hash", nistQuantumSecurityLevel: 4, oid: OID.sha3_384, parameterSetIdentifier: "384", classicalSecurityLevel: 192 })],
  [/^sha3-512$/i, () => ({ primitive: "hash", oid: OID.sha3_512, parameterSetIdentifier: "512", classicalSecurityLevel: 256 })],
  [/^shake(?:128|256)$/i, () => ({ primitive: "xof" })],
  [/^ripemd-?160$/i, () => ({ primitive: "hash", oid: OID.ripemd160, classicalSecurityLevel: 80 })],
  [/^blake2[bs]?(?:-\d+)?$|^blake3$/i, () => ({ primitive: "hash" })],
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
    /^(?:des-ede3|3des|tripledes|desede|des3)(?:-|$)/i,
    (_m, label) => ({
      primitive: "block-cipher",
      nistQuantumSecurityLevel: 0,
      classicalSecurityLevel: 112,
      oid: /^des-ede3-cbc$/i.test(label) ? OID.desEde3Cbc : undefined,
      mode: modeOf(label),
    }),
  ],
  [/^desx(?:-|$)/i, (_m, label) => ({ primitive: "block-cipher", nistQuantumSecurityLevel: 0, mode: modeOf(label) })],
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
  [/^a?rc2(?:-|$)/i, (_m, label) => ({ primitive: "block-cipher", nistQuantumSecurityLevel: 0, oid: /^rc2-cbc$/i.test(label) ? OID.rc2Cbc : undefined, mode: modeOf(label) })],
  [/^(?:rc4|arcfour|arc4)(?:-|$)/i, (_m, label) => ({ primitive: "stream-cipher", nistQuantumSecurityLevel: 0, oid: /^rc4$/i.test(label) ? OID.rc4 : undefined })],
  [/^(?:chacha20-poly1305|xsalsa20-poly1305)$/i, () => ({ primitive: "ae" })],
  [/^(?:x?salsa20|chacha20)$/i, () => ({ primitive: "stream-cipher" })],
  [
    /^camellia(?:-?(128|192|256))?/i,
    (m, label) => ({
      primitive: "block-cipher",
      parameterSetIdentifier: m[1],
      classicalSecurityLevel: m[1] ? Number(m[1]) : undefined,
      mode: modeOf(label),
    }),
  ],
  [/^(?:bf|blowfish)(?:-|$)/i, (_m, label) => ({ primitive: "block-cipher", mode: modeOf(label) })],
];

/** Drop undefined fields, so the JSON never carries `"oid": undefined` noise and equality checks stay simple. */
function compact<T extends object>(value: T): T {
  return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined)) as T;
}

/** Keys whose label leaves their use open: an RSA key can sign or decrypt, an EC key can sign or agree. */
const RSA_KEY = /^rsa(?:-\d+|-\?)?$/i;
const EC_KEY = /^ec$/i;

/**
 * Classify a canonical algorithm label into CycloneDX crypto vocabulary.
 * `usage` refines primitives the label alone leaves open: an RSA key used for
 * encryption (or for TLS 1.2 key transport, which also authenticates the
 * server) is `pke`, and an EC key used only for key establishment is
 * `key-agree`.
 */
export function describeAlgorithm(label: string, usage: readonly CryptoUsage[] = []): AlgorithmDescriptor {
  for (const [pattern, describe] of ALGORITHM_RULES) {
    const match = pattern.exec(label);
    if (!match) continue;
    const descriptor = describe(match, label);
    if (descriptor.primitive === "signature" && !usage.includes("signature")) {
      if (RSA_KEY.test(label) && usage.includes("encryption")) return compact({ ...descriptor, primitive: "pke" });
      if (EC_KEY.test(label) && usage.includes("key-establishment") && !usage.includes("authentication")) {
        return compact({ ...descriptor, primitive: "key-agree", oid: undefined });
      }
    }
    return compact(descriptor);
  }
  return { primitive: "unknown" };
}

/** What a primitive of each CycloneDX kind is used for, in the report's vocabulary. */
const USAGE_BY_PRIMITIVE: Readonly<Record<Primitive, readonly CryptoUsage[]>> = {
  signature: ["signature"],
  kem: ["key-establishment"],
  "key-agree": ["key-establishment"],
  pke: ["encryption"],
  "block-cipher": ["encryption"],
  "stream-cipher": ["encryption"],
  ae: ["encryption"],
  mac: ["authentication"],
  hash: ["hashing"],
  xof: ["hashing"],
  // A password-based or extract-and-expand KDF carries no Shor exposure of its own.
  kdf: ["hashing"],
  other: [],
  unknown: [],
};

/**
 * The use an algorithm label implies, from the same row the CBOM types it
 * with. Empty for a label the vocabulary does not know, and for a key whose
 * use the label leaves open (`RSA-2048`, `EC`), which the risk engine then
 * assesses under both quantum threat models.
 */
export function algorithmUsage(label: string): CryptoUsage[] {
  if (RSA_KEY.test(label) || EC_KEY.test(label)) return [];
  return [...USAGE_BY_PRIMITIVE[describeAlgorithm(label).primitive]];
}
