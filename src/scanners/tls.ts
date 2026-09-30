/**
 * TLS posture scanner.
 *
 * Connects to a host (via an injectable probe so tests stay offline), then
 * classifies the certificate chain and negotiated parameters. Every leaf key is
 * typed from a parsed `KeyObject` and every signature algorithm from the
 * certificate's actual ASN.1 `signatureAlgorithm` field, never from guessing at
 * bytes, so a "vulnerable" verdict is defensible to an auditor.
 *
 * Post-quantum key exchange is established by offering each standardized
 * ML-KEM group on its own over TLS 1.3 and reading back the group the runtime
 * reports as negotiated. The target is resolved and vetted once, and every
 * connection goes to a vetted address, so a rebinding resolver cannot steer a
 * later connection somewhere the guard never saw.
 */
import { connect as tlsConnect, createSecureContext } from "node:tls";
import type { ConnectionOptions, DetailedPeerCertificate, TLSSocket } from "node:tls";
import { isIP } from "node:net";
import type { LookupFunction } from "node:net";
import type { LookupAddress } from "node:dns";
import { X509Certificate } from "node:crypto";
import { certificateSignatureOid, signatureAlgorithmName } from "../asn1";
import {
  REFS,
  curveFriendlyName,
  ir8547Transition,
  isClassicallyWeakKey,
  isPostQuantumKey,
  isQuantumVulnerableKey,
  keyAlgorithmLabel,
  keyPosture,
  meetsCnsa2,
  toKeyType,
} from "../crypto";
import type { KeyType } from "../crypto";
import { resolveAllowedAddress } from "../net-guard";
import type {
  CertificateDetails,
  Confidence,
  CryptoUsage,
  Finding,
  Location,
  PqStatus,
  ProtocolDetails,
  Reference,
  Severity,
} from "../report";

export type { KeyType } from "../crypto";

export interface CertInfo {
  subject: string;
  issuer: string;
  isLeaf: boolean;
  /** Self-issued (subject === issuer), i.e. a trust anchor rather than an intermediate. */
  selfSigned: boolean;
  keyType: KeyType;
  /** The SubjectPublicKeyInfo algorithm OID, retained as provenance. */
  keyOid?: string | null;
  keyBits: number | null;
  curve: string | null;
  /**
   * Friendly signature-algorithm name (e.g. "sha256WithRSAEncryption"), or
   * "unknown". RSASSA-PSS carries its message digest, e.g. "rsassaPss-sha256".
   */
  signatureAlgorithm: string;
  /** The parsed signature-algorithm OID, retained as provenance. */
  signatureOid: string | null;
  validFrom: string;
  validTo: string;
}

/**
 * Aggregate verdict of the post-quantum key-exchange probes: "supported" when
 * the server accepted at least one ML-KEM group over TLS 1.3, "unsupported"
 * when it refused every group that could be offered, "unknown" otherwise.
 */
export type HybridSupport = "supported" | "unsupported" | "unknown";

/**
 * Outcome of offering one key-exchange group on its own.
 *
 * - `accepted`: TLS 1.3 completed and the runtime reported that group as the
 *   negotiated one (Node exposes it as `{ type: "TLSGroup", name }`), or, on a
 *   runtime that reports no TLS 1.3 group (Node 22), TLS 1.3 completed while
 *   only that group was offered; `detail` then says the group was inferred.
 * - `rejected`: the server failed the handshake at the TLS layer.
 * - `inconclusive`: a transport error, a timeout, or a completed handshake the
 *   runtime could not attribute to the group.
 * - `untestable`: the local OpenSSL does not implement the group.
 */
export type GroupOutcome = "accepted" | "rejected" | "inconclusive" | "untestable";

export interface GroupProbeResult {
  group: string;
  outcome: GroupOutcome;
  /** Error code or reason behind the outcome, kept as evidence. */
  detail?: string;
}

export interface TlsScanResult {
  protocol: string | null;
  cipherName: string | null;
  /** Negotiated key-exchange group, e.g. "X25519", "prime256v1", "X25519MLKEM768". */
  groupName: string | null;
  /** Ephemeral key size in bits, when reported (finite-field DHE has no group name). */
  groupBits?: number | null;
  /** Aggregate result of the post-quantum key-exchange probes. */
  hybridKex?: HybridSupport;
  /** Per-group outcomes of the post-quantum key-exchange probes. */
  groupProbes?: GroupProbeResult[];
  /** Why the chain failed validation against the local trust store, or null if it validated. */
  authorizationError?: string | null;
  /** True when only a legacy client offer (TLS 1.0+, OpenSSL security level 0) completed. */
  legacyHandshake?: boolean;
  chain: CertInfo[];
}

export type TlsProbe = (host: string, port: number, timeoutMs: number) => Promise<TlsScanResult>;

export interface TlsScanOptions {
  port?: number;
  timeoutMs?: number;
  probe?: TlsProbe;
  /** Allow scanning non-public addresses (localhost, RFC 1918). Off by default. */
  allowPrivate?: boolean;
}

/** A post-quantum TLS 1.3 key-exchange group and the ML-KEM parameter set inside it. */
interface PqGroup {
  name: string;
  kem: string;
  /** Combined with a classical ECDHE share (RFC 10024) rather than pure ML-KEM. */
  hybrid: boolean;
}

/**
 * The standardized post-quantum groups, each probed on its own. The hybrids are
 * specified in RFC 10024 and the pure groups in draft-ietf-tls-mlkem. CNSA 2.0
 * specifies ML-KEM-1024 for key establishment, so only the last two rows can
 * meet it.
 */
const PQ_GROUPS: readonly PqGroup[] = [
  { name: "X25519MLKEM768", kem: "ML-KEM-768", hybrid: true },
  { name: "SecP256r1MLKEM768", kem: "ML-KEM-768", hybrid: true },
  { name: "MLKEM768", kem: "ML-KEM-768", hybrid: false },
  { name: "SecP384r1MLKEM1024", kem: "ML-KEM-1024", hybrid: true },
  { name: "MLKEM1024", kem: "ML-KEM-1024", hybrid: false },
];

/**
 * Groups the primary handshake offers, in preference order. It leads like a
 * current browser (X25519MLKEM768, then X25519) and then offers every other
 * standardized group, so a server that accepts only a NIST-curve hybrid or only
 * pure ML-KEM still completes a handshake and gets scanned.
 */
const PRIMARY_HANDSHAKE_GROUPS = [
  "X25519MLKEM768",
  "X25519",
  "SecP256r1MLKEM768",
  "SecP384r1MLKEM1024",
  "MLKEM768",
  "MLKEM1024",
  "prime256v1",
  "secp384r1",
  "secp521r1",
  "X448",
  "ffdhe2048",
  "ffdhe3072",
  "ffdhe4096",
];

/**
 * The fallback offer for servers that refuse a TLS 1.2+ handshake at the
 * default security level. Obsolete servers are exactly what the scan must
 * report, so it accepts anything that still authenticates the server.
 */
const LEGACY_OFFER: ConnectionOptions = { minVersion: "TLSv1", ciphers: "ALL:!aNULL:!eNULL:@SECLEVEL=0" };

/** Probes cap their own timeout so six parallel connections cannot stall a scan. */
const PROBE_TIMEOUT_CAP_MS = 8000;

const HYBRID_KEX = /MLKEM|KYBER/i;

/** Extract the common name from an X509Certificate subject/issuer string. */
function commonName(field: string): string {
  for (const line of field.split("\n")) {
    const match = /^\s*CN=(.+?)\s*$/.exec(line);
    if (match?.[1]) return match[1];
  }
  const first = field.split("\n")[0]?.trim();
  return first && first.length > 0 ? first : "unknown";
}

function toIso(value: string | undefined): string {
  if (!value) return "unknown";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toISOString();
}

/** Standard key sizes for algorithms whose strength is fixed, not parameterized. */
function fixedKeyBits(keyType: KeyType): number | null {
  if (keyType === "ed25519") return 256;
  if (keyType === "ed448") return 456;
  return null;
}

// --- DER, for the two fields asn1.ts does not reach -------------------------
//
// asn1.ts reads only the outer signature-algorithm OID. RSASSA-PSS hides its
// digest one level down, in the algorithm parameters, and the key algorithm
// lives in the SubjectPublicKeyInfo. The reader below is total in the same way:
// malformed input yields null, never a throw.

interface DerElement {
  tag: number;
  /** Offset of the first content byte. */
  start: number;
  /** Offset one past the last content byte. */
  end: number;
}

const DER_SEQUENCE = 0x30;
const DER_OID = 0x06;
const DER_CONTEXT_0 = 0xa0;
const RSASSA_PSS_OID = "1.2.840.113549.1.1.10";

/** Read the DER element at `offset`, which must end at or before `limit`. */
function readDer(buf: Buffer, offset: number, limit: number): DerElement | null {
  const tag = buf[offset];
  const first = buf[offset + 1];
  if (tag === undefined || first === undefined || offset + 2 > limit) return null;
  let start = offset + 2;
  let length = first;
  if (first >= 0x80) {
    const count = first & 0x7f;
    if (count === 0 || count > 4 || start + count > limit) return null; // indefinite or absurd
    length = 0;
    for (let i = 0; i < count; i += 1) length = length * 256 + (buf[start + i] ?? 0);
    start += count;
  }
  const end = start + length;
  return end <= limit ? { tag, start, end } : null;
}

/** The direct children of a constructed element, or null if any child is malformed. */
function derChildren(buf: Buffer, parent: DerElement): DerElement[] | null {
  const children: DerElement[] = [];
  let offset = parent.start;
  while (offset < parent.end) {
    const child = readDer(buf, offset, parent.end);
    if (!child) return null;
    children.push(child);
    offset = child.end;
  }
  return children;
}

/** Decode an OBJECT IDENTIFIER element into dotted-decimal form. */
function derOid(buf: Buffer, element: DerElement | undefined): string | null {
  if (!element || element.tag !== DER_OID || element.start >= element.end) return null;
  if (((buf[element.end - 1] ?? 0) & 0x80) !== 0) return null; // truncated final subidentifier
  const arcs: number[] = [];
  let value = 0;
  for (let i = element.start; i < element.end; i += 1) {
    const byte = buf[i] ?? 0;
    value = value * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      arcs.push(value);
      value = 0;
    }
  }
  const [head = 0, ...rest] = arcs;
  const arc0 = head < 40 ? 0 : head < 80 ? 1 : 2;
  return [arc0, head - arc0 * 40, ...rest].join(".");
}

/** The children of an AlgorithmIdentifier SEQUENCE: the OID, then any parameters. */
function algorithmIdentifier(buf: Buffer, element: DerElement | undefined): DerElement[] | null {
  if (element?.tag !== DER_SEQUENCE) return null;
  return derChildren(buf, element);
}

/** The tbsCertificate fields and the outer signatureAlgorithm of a DER certificate. */
function certificateParts(der: Buffer): { tbsFields: DerElement[]; signatureAlgorithm: DerElement } | null {
  const certificate = readDer(der, 0, der.length);
  if (certificate?.tag !== DER_SEQUENCE) return null;
  const [tbs, signatureAlgorithm] = derChildren(der, certificate) ?? [];
  if (tbs?.tag !== DER_SEQUENCE || signatureAlgorithm?.tag !== DER_SEQUENCE) return null;
  const tbsFields = derChildren(der, tbs);
  return tbsFields ? { tbsFields, signatureAlgorithm } : null;
}

/**
 * The SubjectPublicKeyInfo algorithm OID: the seventh tbsCertificate field, or
 * the sixth when the optional `[0] version` is absent.
 */
function spkiAlgorithmOid(der: Buffer): string | null {
  const parts = certificateParts(der);
  if (!parts) return null;
  const spki = parts.tbsFields[parts.tbsFields[0]?.tag === DER_CONTEXT_0 ? 6 : 5];
  if (spki?.tag !== DER_SEQUENCE) return null;
  const [algorithm] = derChildren(der, spki) ?? [];
  return derOid(der, algorithmIdentifier(der, algorithm)?.[0]);
}

/** Message-digest OIDs that can appear in RSASSA-PSS parameters. */
const DIGEST_NAMES: Readonly<Record<string, string>> = {
  "1.3.14.3.2.26": "sha1",
  "2.16.840.1.101.3.4.2.4": "sha224",
  "2.16.840.1.101.3.4.2.1": "sha256",
  "2.16.840.1.101.3.4.2.2": "sha384",
  "2.16.840.1.101.3.4.2.3": "sha512",
  "2.16.840.1.101.3.4.2.5": "sha512-224",
  "2.16.840.1.101.3.4.2.6": "sha512-256",
  "2.16.840.1.101.3.4.2.7": "sha3-224",
  "2.16.840.1.101.3.4.2.8": "sha3-256",
  "2.16.840.1.101.3.4.2.9": "sha3-384",
  "2.16.840.1.101.3.4.2.10": "sha3-512",
};

/**
 * The message digest of an RSASSA-PSS certificate signature (RFC 4055). The
 * `hashAlgorithm` field is `DEFAULT sha1`, so an absent field means SHA-1: the
 * case a bare "rsassaPss" label used to pass off as a sound signature.
 */
function pssDigest(der: Buffer): string | null {
  const parts = certificateParts(der);
  const algorithm = parts ? derChildren(der, parts.signatureAlgorithm) : null;
  if (!algorithm) return null;
  const params = algorithm[1];
  if (!params) return "sha1"; // parameters absent: every field takes its default
  if (params.tag !== DER_SEQUENCE) return null;
  const [first] = derChildren(der, params) ?? [];
  if (first?.tag !== DER_CONTEXT_0) return "sha1"; // hashAlgorithm omitted, so the default
  const [hashAlgorithm] = derChildren(der, first) ?? [];
  const oid = derOid(der, algorithmIdentifier(der, hashAlgorithm)?.[0]);
  return oid ? (DIGEST_NAMES[oid] ?? null) : null;
}

/** ML-KEM SubjectPublicKeyInfo OIDs (NIST CSOR 2.16.840.1.101.3.4.4.1-3). */
const ML_KEM_KEY_OIDS: Readonly<Record<string, string>> = {
  "2.16.840.1.101.3.4.4.1": "ML-KEM-512",
  "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
  "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
};

/**
 * Type a post-quantum key from its SPKI OID, for runtimes whose OpenSSL cannot
 * build a `KeyObject` for it. FIPS 204 and 205 use one OID for both the key and
 * the signature algorithm, so the signature-OID table names ML-DSA and SLH-DSA.
 */
function postQuantumKeyTypeFromOid(oid: string | null): KeyType {
  if (!oid) return "unknown";
  const name = ML_KEM_KEY_OIDS[oid] ?? signatureAlgorithmName(oid);
  return name && /^(?:ML|SLH)-/.test(name) ? toKeyType(name.toLowerCase()) : "unknown";
}

/**
 * Read the subject public key from Node's `KeyObject`. Node throws when its
 * OpenSSL cannot decode the key algorithm; that is a fact about the key, not a
 * reason to abort, so it falls back to the parsed SPKI OID.
 */
function readPublicKey(
  x509: X509Certificate,
  keyOid: string | null,
): { keyType: KeyType; bits: number | null; curve: string | null } {
  try {
    const publicKey = x509.publicKey;
    const reported = toKeyType(publicKey.asymmetricKeyType);
    const keyType = reported === "unknown" ? postQuantumKeyTypeFromOid(keyOid) : reported;
    const details = publicKey.asymmetricKeyDetails ?? {};
    const modulusLength = typeof details.modulusLength === "number" ? details.modulusLength : null;
    const curve = curveFriendlyName(details.namedCurve ?? null);
    return { keyType, bits: modulusLength ?? fixedKeyBits(keyType), curve };
  } catch {
    return { keyType: postQuantumKeyTypeFromOid(keyOid), bits: null, curve: null };
  }
}

/** The signature-algorithm name, with the digest spelled out for RSASSA-PSS. */
function signatureName(der: Buffer, oid: string | null): string {
  if (oid !== RSASSA_PSS_OID) return signatureAlgorithmName(oid) ?? "unknown";
  const digest = pssDigest(der);
  return digest ? `rsassaPss-${digest}` : "unknown";
}

/**
 * Parse a DER certificate into the scanner-facing shape using Node's X.509 and
 * KeyObject APIs plus our ASN.1 readers. Returns null if the bytes are not a
 * parseable certificate (a hostile or truncated chain never throws).
 */
export function parseCertificate(der: Buffer, isLeaf: boolean): CertInfo | null {
  let x509: X509Certificate;
  try {
    x509 = new X509Certificate(der);
  } catch {
    return null;
  }

  const keyOid = spkiAlgorithmOid(x509.raw);
  const key = readPublicKey(x509, keyOid);
  const signatureOid = certificateSignatureOid(x509.raw);

  return {
    subject: commonName(x509.subject),
    issuer: commonName(x509.issuer),
    isLeaf,
    selfSigned: x509.subject === x509.issuer,
    keyType: key.keyType,
    keyOid,
    keyBits: key.bits,
    curve: key.curve,
    signatureAlgorithm: signatureName(x509.raw, signatureOid),
    signatureOid,
    validFrom: toIso(x509.validFrom),
    validTo: toIso(x509.validTo),
  };
}

/** A human-facing description of a certificate's public key, e.g. "RSA-2048", "ECDSA P-256". */
function keyDescription(cert: CertInfo): string {
  if (cert.keyType === "ec") return `ECDSA ${cert.curve ?? "(unknown curve)"}`;
  return keyAlgorithmLabel(cert.keyType, cert.keyBits, cert.curve);
}

/** A parsed certificate as the report carries it, so the CBOM can inventory it with its links. */
function certificateDetails(cert: CertInfo): CertificateDetails {
  return {
    subject: cert.subject,
    issuer: cert.issuer,
    notValidBefore: cert.validFrom,
    notValidAfter: cert.validTo,
    signatureAlgorithm: cert.signatureAlgorithm,
    ...(cert.signatureOid ? { signatureOid: cert.signatureOid } : {}),
    publicKey: keyAlgorithmLabel(cert.keyType, cert.keyBits, cert.curve),
    ...(cert.keyBits !== null ? { publicKeyBits: cert.keyBits } : {}),
  };
}

/** Classify a certificate signature algorithm's post-quantum posture. */
function signaturePosture(name: string): {
  severity: Severity;
  pq_status: PqStatus;
  confidence: Confidence;
  references: Reference[];
  recommendation: string;
} {
  if (name === "unknown") {
    // Fail closed: an unrecognized signature OID on a TLS leaf is a review item,
    // not a clean bill of health. Rating it `info` let the worst algorithms in
    // the corpus through as the quietest finding in the report.
    return {
      severity: "medium",
      pq_status: "unknown",
      confidence: "low",
      references: [REFS.cwe327],
      recommendation:
        "Signature algorithm OID was not recognized; treat as unreviewed and identify the algorithm manually before trusting this chain.",
    };
  }
  if (/^ML-DSA|^SLH-DSA/i.test(name)) {
    const cnsa =
      name === "ML-DSA-87"
        ? "ML-DSA-87 is the CNSA 2.0 signature parameter set."
        : "CNSA 2.0 specifies ML-DSA-87, so this parameter set does not meet CNSA 2.0.";
    return {
      severity: "info",
      pq_status: "safe",
      confidence: "confirmed",
      references: [REFS.fips204, REFS.fips205, REFS.cnsa2],
      recommendation: `Post-quantum signature already in use, keep it and track CA/ecosystem interop. ${cnsa}`,
    };
  }
  if (/^md[245]/i.test(name)) {
    return {
      severity: "critical",
      pq_status: "vulnerable",
      confidence: "confirmed",
      references: [REFS.sp800131a, REFS.cwe327, REFS.fips204],
      recommendation:
        "MD2/MD4/MD5 signature: forgeable with a classical chosen-prefix collision today (a rogue CA certificate was forged this way in 2008, and Flame exploited it in 2012). Re-issue on SHA-256+ immediately; this is not a quantum-timeline item.",
    };
  }
  if (/sha1/i.test(name)) {
    return {
      severity: "high",
      pq_status: "vulnerable",
      confidence: "confirmed",
      references: [REFS.sp800131a, REFS.cwe327, REFS.fips204],
      recommendation:
        "SHA-1 signature: broken classically today (SP 800-131A disallows it) and quantum-vulnerable. Re-issue on SHA-256+ now, and plan ML-DSA / hybrid certificates.",
    };
  }
  return {
    // Classically sound but pre-quantum: a migration item, not a live break.
    // Rating it `high` made `--fail-on high` red for every host on the internet.
    severity: "medium",
    pq_status: "vulnerable",
    confidence: "confirmed",
    references: [REFS.fips204, REFS.cnsa2],
    recommendation: "Classical signature; move to ML-DSA / hybrid certificates when CA support arrives.",
  };
}

/** What the leaf-key finding tells the reader to do, by key family and strength. */
function leafKeyRecommendation(leaf: CertInfo, pqStatus: PqStatus): string {
  if (isClassicallyWeakKey(leaf.keyType, leaf.keyBits, leaf.curve)) {
    return "Below the SP 800-131A minimum (RSA/DSA ≥ 2048 bits, ECC ≥ 224-bit curve): this key is at risk from classical attack today. Re-key now, then plan the post-quantum migration.";
  }
  if (isPostQuantumKey(leaf.keyType)) {
    const label = keyAlgorithmLabel(leaf.keyType, leaf.keyBits, leaf.curve);
    return meetsCnsa2(leaf.keyType)
      ? `Post-quantum key (${label}), the CNSA 2.0 parameter set. Keep it and track client interop.`
      : `Post-quantum key (${label}), FIPS-approved. CNSA 2.0 specifies ML-DSA-87 for signatures and ML-KEM-1024 for key establishment, so this parameter set does not meet CNSA 2.0 where that applies.`;
  }
  if (leaf.keyType === "dsa") {
    return "DSA is no longer approved for signature generation (FIPS 186-5): replace the key now, then plan the post-quantum migration.";
  }
  if (pqStatus !== "vulnerable") return "Confirm the key type and document it in the crypto inventory.";
  const schedule = ir8547Transition(leaf.keyType, leaf.keyBits, leaf.curve);
  const dates = !schedule
    ? ""
    : schedule.deprecatedAfter
      ? ` NIST IR 8547 (draft) deprecates this 112-bit strength after ${schedule.deprecatedAfter} and disallows it after ${schedule.disallowedAfter}.`
      : ` NIST IR 8547 (draft) disallows it after ${schedule.disallowedAfter}.`;
  return `Classically sound but pre-quantum. Plan migration to a post-quantum / hybrid certificate (ML-DSA) as CA support arrives.${dates}`;
}

/**
 * The certificates above the leaf that the server itself sent.
 *
 * Node's `getPeerCertificate(true)` keeps walking `issuerCertificate` into the
 * local trust store, so the last entry is usually a root the server never sent;
 * roots are self-signed, so dropping them leaves only real intermediates.
 */
function serverIntermediates(chain: CertInfo[]): CertInfo[] {
  return chain.slice(1).filter((c) => !c.selfSigned);
}

type CertPosture = "classical" | "post-quantum" | "unknown";

/**
 * An intermediate is only as quantum-safe as the weaker of its own key and the
 * signature over it: a post-quantum key signed with RSA is still forgeable.
 */
function certificatePosture(cert: CertInfo): CertPosture {
  const signature = signaturePosture(cert.signatureAlgorithm).pq_status;
  if (isQuantumVulnerableKey(cert.keyType) || signature === "vulnerable") return "classical";
  if (isPostQuantumKey(cert.keyType) && signature === "safe") return "post-quantum";
  return "unknown";
}

/** Assess the intermediates, from each one's parsed key type and signature algorithm. */
function evaluateChain(chain: CertInfo[]): Finding | null {
  const intermediates = serverIntermediates(chain);
  if (intermediates.length === 0) return null;

  const postures = intermediates.map(certificatePosture);
  const count = (posture: CertPosture): number => postures.filter((p) => p === posture).length;
  const total = intermediates.length;
  const classical = count("classical");
  const postQuantum = count("post-quantum");
  const unknown = count("unknown");
  const summary =
    classical === total
      ? "using classical crypto"
      : postQuantum === total
        ? "using post-quantum keys and signatures"
        : [
            `${classical} of ${total} using classical crypto`,
            postQuantum > 0 ? `${postQuantum} post-quantum` : "",
            unknown > 0 ? `${unknown} of unrecognized key or signature type` : "",
          ]
            .filter(Boolean)
            .join(", ");

  return {
    id: "CSW-TLS-003",
    ruleId: "tls/chain-classical",
    severity: postQuantum === total ? "info" : "medium",
    category: "tls",
    title: `Certificate chain has ${total} intermediate(s) ${summary}`,
    evidence: intermediates
      .map((c) => `${c.subject} (${keyDescription(c)} key, ${c.signatureAlgorithm} signature)`)
      .join(" → "),
    pq_status: classical > 0 ? "vulnerable" : unknown > 0 ? "unknown" : "safe",
    confidence: unknown === 0 ? "confirmed" : "high",
    certificates: intermediates.map(certificateDetails),
    references: [REFS.fips204, REFS.cnsa2],
    recommendation:
      classical > 0
        ? "The whole chain must migrate; classical intermediates remain quantum-vulnerable."
        : unknown > 0
          ? "Identify the unrecognized intermediate algorithms before relying on this chain's post-quantum posture."
          : "Post-quantum intermediates in place; keep them and track client interop.",
  };
}

/**
 * A classically broken (MD5, SHA-1) or unrecognized signature on an
 * intermediate gets its own finding, exactly as it would on the leaf: a SHA-1
 * intermediate is forgeable today, whatever the quantum timeline.
 */
function evaluateIntermediateSignatures(chain: CertInfo[], target: string): Finding[] {
  return serverIntermediates(chain).flatMap((cert): Finding[] => {
    const sig = signaturePosture(cert.signatureAlgorithm);
    const flagged = sig.pq_status === "unknown" || sig.severity === "critical" || sig.severity === "high";
    if (!flagged) return [];
    return [
      {
        id: "CSW-TLS-006",
        ruleId: "tls/intermediate-signature",
        severity: sig.severity,
        category: "tls",
        title: `Intermediate signature algorithm: ${cert.signatureAlgorithm}`,
        evidence: `${target} (${cert.subject})`,
        pq_status: sig.pq_status,
        confidence: sig.confidence,
        algorithm: cert.signatureAlgorithm,
        ...(cert.signatureOid ? { oid: cert.signatureOid } : {}),
        certificates: [certificateDetails(cert)],
        references: sig.references,
        recommendation: sig.recommendation,
      },
    ];
  });
}

/** Report a chain that failed validation (trust store or hostname) instead of ignoring it. */
function evaluateChainTrust(result: TlsScanResult, target: string): Finding | null {
  if (!result.authorizationError) return null;
  return {
    id: "CSW-TLS-008",
    ruleId: "tls/chain-untrusted",
    severity: "medium",
    category: "tls",
    title: `Certificate chain did not validate (${result.authorizationError})`,
    evidence: target,
    pq_status: "unknown",
    confidence: "confirmed",
    recommendation:
      "The served chain failed validation against this machine's trust store or the hostname check. The key and signature findings describe the certificates as served and do not vouch for them; an untrusted chain on a public host can also mean the scan itself was intercepted.",
  };
}

/** What a single handshake cannot show, stated so the report is not read as more than it is. */
const PROTOCOL_SCOPE =
  "Not assessed: other protocol versions and cipher suites the server may also accept (only the ones negotiated for this client offer were observed).";

/** The negotiated session in structured form: `TLSv1.3` becomes version `1.3`, `TLSv1` becomes `1.0`. */
function protocolDetails(result: TlsScanResult): ProtocolDetails {
  const version = /^TLSv(\d)(?:\.(\d))?$/.exec(result.protocol ?? "");
  return {
    type: "tls",
    ...(version ? { version: `${version[1] ?? ""}.${version[2] ?? "0"}` } : {}),
    ...(result.cipherName ? { cipherSuite: result.cipherName } : {}),
    ...(result.groupName ? { group: result.groupName } : {}),
  };
}

function evaluateProtocol(result: TlsScanResult, target: string): Finding | null {
  const protocol = result.protocol;
  if (!protocol) return null;
  const evidence = [
    target,
    result.cipherName ? `cipher=${result.cipherName}` : "",
    result.legacyHandshake ? "(completed only with a legacy TLS 1.0+, security-level-0 client offer)" : "",
  ]
    .filter(Boolean)
    .join(" ");
  const base = {
    id: "CSW-TLS-004",
    ruleId: "tls/negotiated-protocol",
    category: "tls" as const,
    evidence,
    confidence: "confirmed" as const,
    protocol: protocolDetails(result),
    references: [REFS.hybridKex, REFS.mlkemKex],
  };

  if (protocol === "TLSv1.3") {
    return {
      ...base,
      severity: "info",
      title: "Negotiated TLSv1.3",
      pq_status: "transitional",
      recommendation: `TLS 1.3 is required for post-quantum key exchange, keep it enabled. ${PROTOCOL_SCOPE}`,
    };
  }
  if (protocol === "TLSv1.2") {
    // Every ML-KEM group is a TLS 1.3 construction, so a TLS 1.2 session can
    // only ever use classical key exchange.
    return {
      ...base,
      severity: "medium",
      title: "Negotiated TLSv1.2",
      pq_status: "vulnerable",
      recommendation: `TLS 1.2 cannot carry post-quantum key exchange: the ML-KEM groups are defined only for TLS 1.3. Enable TLS 1.3. ${PROTOCOL_SCOPE}`,
    };
  }
  return {
    ...base,
    severity: "high",
    title: `Obsolete protocol negotiated (${protocol})`,
    pq_status: "vulnerable",
    recommendation: `Disable TLS < 1.2 (deprecated by RFC 8996) and adopt TLS 1.3 to support post-quantum key exchange. ${PROTOCOL_SCOPE}`,
  };
}

function evaluateValidity(cert: CertInfo, evidence: string, now: Date): Finding | null {
  const expiry = new Date(cert.validTo);
  if (Number.isNaN(expiry.getTime())) return null;
  const msLeft = expiry.getTime() - now.getTime();
  if (msLeft < 0) {
    return {
      id: "CSW-TLS-007",
      ruleId: "tls/leaf-expired",
      severity: "high",
      category: "tls",
      title: "Leaf certificate has expired",
      evidence: `${evidence} valid_to=${cert.validTo}`,
      pq_status: "unknown",
      confidence: "confirmed",
      recommendation: "Renew the certificate; an expired chain blocks any crypto-agility rollout.",
    };
  }
  const thirtyDays = 30 * 24 * 60 * 60 * 1000;
  if (msLeft < thirtyDays) {
    return {
      id: "CSW-TLS-007",
      ruleId: "tls/leaf-expiring",
      severity: "low",
      category: "tls",
      title: "Leaf certificate expires within 30 days",
      evidence: `${evidence} valid_to=${cert.validTo}`,
      pq_status: "unknown",
      confidence: "confirmed",
      recommendation: "Schedule renewal; pair it with a move to crypto-agile certificate tooling.",
    };
  }
  return null;
}

// --- Key exchange ------------------------------------------------------------

/** Identify a post-quantum group by name, including ones outside the probed set. */
function pqGroup(name: string | null | undefined): PqGroup | null {
  if (!name || !HYBRID_KEX.test(name)) return null;
  const known = PQ_GROUPS.find((g) => g.name.toLowerCase() === name.toLowerCase());
  if (known) return known;
  const level = /MLKEM(512|768|1024)/i.exec(name)?.[1];
  return { name, kem: level ? `ML-KEM-${level}` : "pre-standard Kyber", hybrid: !/^MLKEM\d+$/i.test(name) };
}

/** A classical key exchange as negotiated, labelled for the inventory. */
interface ClassicalKex {
  label: string;
  forwardSecret: boolean;
  classicallyWeak: boolean;
}

/**
 * RSA key-transport suites carry no key-exchange prefix in OpenSSL naming
 * (e.g. "AES256-GCM-SHA384", "DES-CBC3-SHA"), unlike "ECDHE-…" and "DHE-…".
 */
const RSA_KEY_TRANSPORT = /^(?:AES|ARIA|CAMELLIA|DES|IDEA|NULL|RC2|RC4|SEED)/i;

function finiteFieldKex(prefix: string, bits: number | null): ClassicalKex {
  return {
    label: bits === null ? prefix : `${prefix}-${bits}`,
    forwardSecret: true,
    classicallyWeak: bits !== null && bits < 2048,
  };
}

/** Describe the classical key exchange this session used, or null if it cannot be told. */
function classicalKeyExchange(result: TlsScanResult): ClassicalKex | null {
  const cipher = result.cipherName ?? "";
  const bits = result.groupBits ?? null;
  const tls13 = result.protocol === "TLSv1.3" || cipher.startsWith("TLS_");
  if (!tls13 && RSA_KEY_TRANSPORT.test(cipher)) {
    return { label: "static-RSA-key-exchange", forwardSecret: false, classicallyWeak: false };
  }
  if (!tls13 && /^(?:DHE|EDH)-/.test(cipher)) return finiteFieldKex("DHE", bits);
  if (result.groupName && !pqGroup(result.groupName)) {
    const curve = curveFriendlyName(result.groupName) ?? result.groupName;
    return { label: `ECDHE-${curve}`, forwardSecret: true, classicallyWeak: false };
  }
  if (!tls13 && /^(?:ECDHE|EECDH)-/.test(cipher)) return { label: "ECDHE", forwardSecret: true, classicallyWeak: false };
  if (tls13 && bits !== null) return finiteFieldKex("FFDHE", bits);
  return null;
}

/**
 * Per-group probe outcomes. A caller-supplied aggregate verdict (the older,
 * single-group probe API) describes X25519MLKEM768 alone.
 */
function probeResults(result: TlsScanResult): GroupProbeResult[] {
  if (result.groupProbes) return result.groupProbes;
  if (result.hybridKex === "supported") return [{ group: "X25519MLKEM768", outcome: "accepted" }];
  if (result.hybridKex === "unsupported") return [{ group: "X25519MLKEM768", outcome: "rejected" }];
  return [];
}

/** Groups the server demonstrably accepted: the probes, plus a PQ group the primary handshake negotiated. */
function acceptedGroups(result: TlsScanResult, probes: GroupProbeResult[]): PqGroup[] {
  const names = [result.groupName, ...probes.filter((p) => p.outcome === "accepted").map((p) => p.group)];
  const accepted: PqGroup[] = [];
  for (const name of names) {
    const group = pqGroup(name);
    if (group && !accepted.some((g) => g.name.toLowerCase() === group.name.toLowerCase())) accepted.push(group);
  }
  return accepted;
}

function kexEvidence(target: string, result: TlsScanResult, probes: GroupProbeResult[]): string {
  const parts = [target];
  if (result.groupName) parts.push(`group=${result.groupName}`);
  if (result.cipherName) parts.push(`cipher=${result.cipherName}`);
  for (const outcome of ["accepted", "rejected", "inconclusive", "untestable"] as const) {
    const groups = probes
      .filter((p) => p.outcome === outcome)
      .map((p) => (p.detail && outcome !== "rejected" ? `${p.group} (${p.detail})` : p.group));
    if (groups.length > 0) parts.push(`${outcome}=${groups.join(", ")}`);
  }
  return parts.join(" ");
}

const KEX_BASE = { id: "CSW-TLS-005", ruleId: "tls/hybrid-kex", category: "tls" as const };

/** Probe detail for a group attributed from the offer because the runtime does not name TLS 1.3 groups. */
const INFERRED_GROUP = "inferred from the single offered group; this runtime does not report the negotiated TLS 1.3 group";
const ENABLE_PQ_KEX =
  "Enable X25519MLKEM768 (SecP384r1MLKEM1024 or MLKEM1024 where CNSA 2.0 applies) so session keys resist harvest-now-decrypt-later attacks.";

/** Below TLS 1.3 there is no ML-KEM group to negotiate, whatever a probe claimed. */
function preTls13KeyExchange(result: TlsScanResult, target: string, probes: GroupProbeResult[]): Finding {
  const protocol = result.protocol ?? "TLS < 1.3";
  const kex = classicalKeyExchange(result);
  const noForwardSecrecy = kex?.forwardSecret === false;
  const recommendation = noForwardSecrecy
    ? "Static RSA key transport: whoever records this traffic and later recovers the one RSA key (stolen today, or broken by a quantum computer later) decrypts every recorded session. Disable RSA key-exchange suites and enable TLS 1.3 with X25519MLKEM768."
    : kex?.classicallyWeak
      ? `${kex.label} is below the SP 800-131A 2048-bit floor and breakable classically. Disable it, and enable TLS 1.3 with X25519MLKEM768.`
      : `ML-KEM key-exchange groups are defined only for TLS 1.3. Enable TLS 1.3. ${ENABLE_PQ_KEX}`;
  return {
    ...KEX_BASE,
    severity: noForwardSecrecy || kex?.classicallyWeak ? "high" : "medium",
    title: noForwardSecrecy
      ? `RSA key exchange without forward secrecy (${protocol}); no post-quantum key exchange`
      : `No post-quantum key exchange: ${protocol} negotiated ${kex?.label ?? "a classical key exchange"}`,
    evidence: kexEvidence(target, result, probes),
    pq_status: "vulnerable",
    confidence: "confirmed",
    ...(kex ? { algorithm: kex.label } : {}),
    references: kex?.classicallyWeak ? [REFS.hybridKex, REFS.fips203, REFS.sp800131a] : [REFS.hybridKex, REFS.fips203],
    recommendation,
  };
}

function pqKeyExchangeFinding(
  result: TlsScanResult,
  target: string,
  accepted: PqGroup[],
  probes: GroupProbeResult[],
): Finding {
  const names = accepted.map((g) => g.name).join(", ");
  const allHybrid = accepted.every((g) => g.hybrid);
  const cnsaKem = accepted.some((g) => g.kem === "ML-KEM-1024");
  const references: Reference[] = [
    ...(accepted.some((g) => g.hybrid) ? [REFS.hybridKex, REFS.hybridDesign] : []),
    ...(allHybrid ? [] : [REFS.mlkemKex]),
    REFS.fips203,
    REFS.cnsa2,
  ];
  const kems = [...new Set(accepted.map((g) => g.kem))].join(", ");
  // A group the runtime named is parsed evidence; one attributed from the offer is a protocol inference.
  const allNamed = accepted.every(
    (g) =>
      g.name.toLowerCase() === result.groupName?.toLowerCase() ||
      probes.some((p) => p.outcome === "accepted" && p.detail === undefined && p.group.toLowerCase() === g.name.toLowerCase()),
  );
  const cnsa = cnsaKem
    ? "ML-KEM-1024 is available, the key-establishment parameter set CNSA 2.0 specifies."
    : `Not CNSA 2.0 compliant: CNSA 2.0 specifies ML-KEM-1024, so ${kems} groups are transitional where it applies; add SecP384r1MLKEM1024 or MLKEM1024 there.`;
  return {
    ...KEX_BASE,
    severity: "info",
    title: `Server supports ${allHybrid ? "hybrid " : ""}post-quantum key exchange (${names})`,
    evidence: kexEvidence(target, result, probes),
    pq_status: allHybrid ? "transitional" : "safe",
    confidence: allNamed ? "confirmed" : "high",
    algorithm: accepted[0]?.name ?? "hybrid-kex",
    references,
    recommendation: `Keep it enabled: sessions with clients that offer these groups resist harvest-now-decrypt-later, while clients that do not still get classical key exchange. ${cnsa}`,
  };
}

/** TLS 1.3 (or unknown protocol) and no accepted group: say exactly how much was tested. */
function noPqKeyExchangeFinding(result: TlsScanResult, target: string, probes: GroupProbeResult[]): Finding {
  const kex = classicalKeyExchange(result);
  const evidence = kexEvidence(target, result, probes);
  const rejected = probes.filter((p) => p.outcome === "rejected").map((p) => p.group);

  if (rejected.length > 0) {
    const untried = PQ_GROUPS.map((g) => g.name).filter((name) => !rejected.includes(name));
    return {
      ...KEX_BASE,
      severity: "medium",
      title: `No tested post-quantum key-exchange group accepted (tried: ${rejected.join(", ")})`,
      evidence,
      pq_status: "vulnerable",
      // Refusals are hard evidence, but only for the groups actually offered.
      confidence: untried.length === 0 ? "high" : "medium",
      ...(kex ? { algorithm: kex.label } : {}),
      references: [REFS.hybridKex, REFS.mlkemKex, REFS.fips203],
      recommendation:
        untried.length === 0 ? ENABLE_PQ_KEX : `${ENABLE_PQ_KEX} Not conclusively tested: ${untried.join(", ")}.`,
    };
  }
  if (probes.length > 0 && probes.every((p) => p.outcome === "untestable")) {
    return {
      ...KEX_BASE,
      severity: "info",
      title: "Post-quantum key exchange not tested: the local TLS runtime lacks ML-KEM groups",
      evidence,
      pq_status: "unknown",
      confidence: "low",
      references: [REFS.hybridKex, REFS.fips203],
      recommendation:
        "A limit of the scanning machine, not a verdict on the server. Re-run on a Node.js build whose OpenSSL is 3.5 or later (see process.versions.openssl) to probe the ML-KEM groups.",
    };
  }
  if (kex) {
    // Only the group this client was given, not what the server could do.
    return {
      ...KEX_BASE,
      severity: "medium",
      title: "No post-quantum key exchange negotiated",
      evidence,
      pq_status: "vulnerable",
      confidence: "medium",
      algorithm: kex.label,
      references: [REFS.hybridKex, REFS.fips203],
      recommendation: ENABLE_PQ_KEX,
    };
  }
  return {
    ...KEX_BASE,
    severity: "info",
    title: "Post-quantum key-exchange support could not be determined",
    evidence,
    pq_status: "unknown",
    confidence: "low",
    references: [REFS.hybridKex],
    recommendation: "Could not determine post-quantum key-exchange support; confirm server-side whether X25519MLKEM768 is enabled.",
  };
}

function evaluateKeyExchange(result: TlsScanResult, target: string): Finding {
  const probes = probeResults(result);
  if (result.protocol && result.protocol !== "TLSv1.3") return preTls13KeyExchange(result, target, probes);
  const accepted = acceptedGroups(result, probes);
  if (accepted.length > 0) return pqKeyExchangeFinding(result, target, accepted, probes);
  return noPqKeyExchangeFinding(result, target, probes);
}

/**
 * What the leaf key does in this session. It authenticates the handshake,
 * except under static RSA key transport, where it also decrypts the premaster
 * secret: then recorded sessions fall with the key, a harvest-now exposure.
 */
function leafKeyUsage(result: TlsScanResult): CryptoUsage[] {
  const keyTransport = result.protocol !== "TLSv1.3" && classicalKeyExchange(result)?.forwardSecret === false;
  return keyTransport ? ["encryption", "authentication"] : ["authentication"];
}

/** Analyze a completed handshake and return findings. Pure, drives the tests. */
export function analyzeTls(
  result: TlsScanResult,
  target = "tls",
  now: Date = new Date(),
  location?: Location,
): Finding[] {
  const findings: Finding[] = [];
  const leaf = result.chain[0];

  if (!leaf) {
    findings.push({
      id: "CSW-TLS-000",
      ruleId: "tls/no-leaf",
      severity: "info",
      category: "tls",
      title: "No leaf certificate could be read",
      evidence: target,
      pq_status: "unknown",
      confidence: "confirmed",
      recommendation: "Verify the host serves a certificate on the scanned port.",
    });
  } else {
    const subjectEvidence = `${target} (${leaf.subject})`;
    const posture = keyPosture(leaf.keyType, leaf.keyBits, leaf.curve);
    findings.push({
      id: "CSW-TLS-001",
      ruleId: "tls/leaf-public-key",
      severity: posture.severity,
      category: "tls",
      title: `Leaf public key: ${keyDescription(leaf)}`,
      evidence: subjectEvidence,
      pq_status: posture.pq_status,
      confidence: leaf.keyType === "unknown" ? "low" : "confirmed",
      algorithm: keyAlgorithmLabel(leaf.keyType, leaf.keyBits, leaf.curve),
      ...(leaf.keyOid ? { oid: leaf.keyOid } : {}),
      usage: leafKeyUsage(result),
      references: posture.references,
      recommendation: leafKeyRecommendation(leaf, posture.pq_status),
    });

    const sig = signaturePosture(leaf.signatureAlgorithm);
    findings.push({
      id: "CSW-TLS-002",
      ruleId: "tls/leaf-signature",
      severity: sig.severity,
      category: "tls",
      title: `Leaf signature algorithm: ${leaf.signatureAlgorithm}`,
      evidence: subjectEvidence,
      pq_status: sig.pq_status,
      confidence: sig.confidence,
      algorithm: leaf.signatureAlgorithm,
      ...(leaf.signatureOid ? { oid: leaf.signatureOid } : {}),
      certificates: [certificateDetails(leaf)],
      references: sig.references,
      recommendation: sig.recommendation,
    });

    const validity = evaluateValidity(leaf, target, now);
    if (validity) findings.push(validity);
  }

  const chainFinding = evaluateChain(result.chain);
  if (chainFinding) findings.push(chainFinding);
  findings.push(...evaluateIntermediateSignatures(result.chain, target));
  const trustFinding = evaluateChainTrust(result, target);
  if (trustFinding) findings.push(trustFinding);

  const protocolFinding = evaluateProtocol(result, target);
  if (protocolFinding) findings.push(protocolFinding);
  findings.push(evaluateKeyExchange(result, target));

  // Network findings have no file path; the host/port IS their location, and
  // SARIF consumers drop results that carry none.
  if (location) for (const finding of findings) finding.location = { ...location };

  return findings;
}

// --- Network -----------------------------------------------------------------

function collectChain(leaf: DetailedPeerCertificate): CertInfo[] {
  const chain: CertInfo[] = [];
  const seen = new Set<string>();
  let cert: DetailedPeerCertificate | undefined = leaf;
  let isLeaf = true;
  while (cert && cert.fingerprint256 && !seen.has(cert.fingerprint256)) {
    seen.add(cert.fingerprint256);
    if (cert.raw) {
      const parsed = parseCertificate(cert.raw, isLeaf);
      if (parsed) chain.push(parsed);
    }
    isLeaf = false;
    const next: DetailedPeerCertificate | undefined = cert.issuerCertificate;
    if (!next || next.fingerprint256 === cert.fingerprint256) break;
    cert = next;
  }
  return chain;
}

/** A scan target resolved once and vetted: every connection goes to one of these addresses. */
interface ResolvedTarget {
  /** The name (or IP literal) given to `tls.connect`. */
  host: string;
  /** SNI and certificate-identity name; absent for an IP literal, which SNI forbids. */
  servername?: string;
  addresses: LookupAddress[];
}

/**
 * Resolve `host` once through the shared SSRF guard, which fails closed on a
 * lookup error, a non-IP answer or a non-canonical numeric host, and refuses
 * the whole name if any one address is blocked (the kernel may connect to any
 * of them). Every connection then goes to one of these addresses.
 */
async function resolveTarget(host: string, allowPrivate: boolean): Promise<ResolvedTarget> {
  const bare = host.replace(/^\[(.*)\]$/, "$1"); // strip IPv6 brackets
  const addresses = await resolveAllowedAddress(bare, allowPrivate);
  return isIP(bare) === 0 ? { host: bare, servername: bare, addresses } : { host: bare, addresses };
}

/**
 * A `lookup` for `tls.connect` that answers only with the vetted addresses.
 * Without it Node resolves the name again at connect time, and a rebinding
 * resolver can answer that second query with an internal address. Handing Node
 * the whole vetted list keeps its happy-eyeballs fallback across families.
 */
function pinnedLookup(addresses: readonly LookupAddress[]): LookupFunction {
  return (_hostname, options, callback) => {
    const family = options.family === "IPv4" ? 4 : options.family === "IPv6" ? 6 : (options.family ?? 0);
    const matching = family === 0 ? [...addresses] : addresses.filter((a) => a.family === family);
    const first = matching[0];
    if (!first) {
      callback(Object.assign(new Error(`No vetted IPv${family} address`), { code: "ENOTFOUND" }), "");
      return;
    }
    if (options.all) callback(null, matching);
    else callback(null, first.address, first.family);
  };
}

const localGroupSupport = new Map<string, boolean>();

/** Does the local OpenSSL implement a key-exchange group? Unknown names make it throw. */
function locallySupported(group: string): boolean {
  let supported = localGroupSupport.get(group);
  if (supported === undefined) {
    try {
      createSecureContext({ ecdhCurve: group });
      supported = true;
    } catch {
      supported = false;
    }
    localGroupSupport.set(group, supported);
  }
  return supported;
}

function connectOptions(target: ResolvedTarget, port: number): ConnectionOptions {
  return {
    host: target.host,
    port,
    ...(target.servername ? { servername: target.servername } : {}),
    lookup: pinnedLookup(target.addresses),
    rejectUnauthorized: false,
  };
}

function errorCode(err: unknown): string | undefined {
  const code: unknown = err && typeof err === "object" && "code" in err ? err.code : undefined;
  return typeof code === "string" ? code : undefined;
}

function isTlsLayerError(err: unknown): boolean {
  return errorCode(err)?.startsWith("ERR_SSL_") ?? false;
}

/** Open a TLS connection and resolve once the handshake completes; the caller ends the socket. */
function openTls(options: ConnectionOptions, timeoutMs: number): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    let socket: TLSSocket;
    try {
      socket = tlsConnect(options, () => {
        socket.setTimeout(0);
        resolve(socket);
      });
    } catch (err) {
      reject(err instanceof Error ? err : new Error(String(err)));
      return;
    }
    socket.on("error", (err) => {
      socket.destroy();
      reject(err);
    });
    socket.setTimeout(timeoutMs, () => {
      const message = `TLS handshake to ${options.host ?? "host"}:${options.port ?? ""} timed out after ${timeoutMs}ms`;
      socket.destroy(Object.assign(new Error(message), { code: "ETIMEDOUT" }));
    });
  });
}

/** The negotiated group name and ephemeral key size, as far as the runtime reports them. */
function ephemeralKey(socket: TLSSocket): { name: string | null; size: number | null } {
  const info: unknown = socket.getEphemeralKeyInfo();
  if (!info || typeof info !== "object") return { name: null, size: null };
  const { name, size } = info as { name?: unknown; size?: unknown };
  return { name: typeof name === "string" ? name : null, size: typeof size === "number" ? size : null };
}

function authorizationFailure(socket: TLSSocket): string | null {
  if (socket.authorized) return null;
  const reason: unknown = socket.authorizationError;
  if (typeof reason === "string") return reason;
  return reason instanceof Error ? reason.message : "unverified";
}

type HandshakeResult = Omit<TlsScanResult, "hybridKex" | "groupProbes">;

async function readHandshake(
  target: ResolvedTarget,
  port: number,
  timeoutMs: number,
  offer: ConnectionOptions,
): Promise<HandshakeResult> {
  const options = { ...connectOptions(target, port), ALPNProtocols: ["h2", "http/1.1"], ...offer };
  const socket = await openTls(options, timeoutMs);
  try {
    const ephemeral = ephemeralKey(socket);
    return {
      protocol: socket.getProtocol(),
      cipherName: socket.getCipher()?.name ?? null,
      groupName: ephemeral.name,
      groupBits: ephemeral.size,
      authorizationError: authorizationFailure(socket),
      chain: collectChain(socket.getPeerCertificate(true)),
    };
  } finally {
    socket.end();
  }
}

/**
 * Perform the primary handshake and read the certificate chain and parameters.
 * A server that refuses a modern offer at the TLS layer gets one retry with the
 * legacy offer, so a TLS 1.0 server is reported rather than aborting the scan.
 */
async function handshake(target: ResolvedTarget, port: number, timeoutMs: number): Promise<HandshakeResult> {
  const groups = PRIMARY_HANDSHAKE_GROUPS.filter(locallySupported).join(":");
  const modern: ConnectionOptions = groups ? { ecdhCurve: groups } : {};
  try {
    return await readHandshake(target, port, timeoutMs, modern);
  } catch (err) {
    if (!isTlsLayerError(err)) throw err;
    const legacy = await readHandshake(target, port, timeoutMs, { ...modern, ...LEGACY_OFFER }).catch(() => null);
    if (!legacy) throw err;
    return { ...legacy, legacyHandshake: true };
  }
}

/**
 * Offer exactly one group over TLS 1.3 only. It counts as accepted only when
 * the handshake completes as TLS 1.3 and the runtime names that group as the
 * negotiated one: without `minVersion` a TLS 1.2 server would complete a
 * classical handshake (even static RSA) and pass as post-quantum.
 */
async function probeGroup(
  target: ResolvedTarget,
  port: number,
  timeoutMs: number,
  group: string,
): Promise<GroupProbeResult> {
  if (!locallySupported(group)) {
    const openssl = process.versions.openssl ?? "(unknown version)";
    return { group, outcome: "untestable", detail: `local OpenSSL ${openssl} lacks it` };
  }
  let socket: TLSSocket;
  try {
    socket = await openTls({ ...connectOptions(target, port), minVersion: "TLSv1.3", ecdhCurve: group }, timeoutMs);
  } catch (err) {
    const code = errorCode(err) ?? (err instanceof Error ? err.message : String(err));
    // The primary handshake shows the host speaks TLS, so a TLS-layer failure
    // while offering only this group is a refusal. Transport errors prove nothing.
    return { group, outcome: isTlsLayerError(err) ? "rejected" : "inconclusive", detail: code };
  }
  const protocol = socket.getProtocol();
  const negotiated = ephemeralKey(socket).name;
  socket.end();
  if (protocol === "TLSv1.3" && negotiated?.toLowerCase() === group.toLowerCase()) {
    return { group, outcome: "accepted" };
  }
  if (protocol === "TLSv1.3" && negotiated === null) {
    // RFC 8446 lets the server key the handshake only with a group the client
    // offered, and a fresh TLS 1.3 handshake cannot skip (EC)DHE, so completing
    // one while offering only this group means it was used.
    return { group, outcome: "accepted", detail: INFERRED_GROUP };
  }
  return {
    group,
    outcome: "inconclusive",
    detail: `completed as ${protocol ?? "unknown protocol"} with group ${negotiated ?? "not reported by this runtime"}`,
  };
}

function summarizeProbes(probes: GroupProbeResult[]): HybridSupport {
  if (probes.some((p) => p.outcome === "accepted")) return "supported";
  if (probes.some((p) => p.outcome === "rejected")) return "unsupported";
  return "unknown";
}

/** The live probe, bound to addresses that were resolved and vetted once. */
function networkProbe(target: ResolvedTarget): TlsProbe {
  return async (_host, port, timeoutMs) => {
    const probeTimeout = Math.min(timeoutMs, PROBE_TIMEOUT_CAP_MS);
    const [base, groupProbes] = await Promise.all([
      handshake(target, port, timeoutMs),
      Promise.all(PQ_GROUPS.map((g) => probeGroup(target, port, probeTimeout, g.name))),
    ]);
    return { ...base, hybridKex: summarizeProbes(groupProbes), groupProbes };
  };
}

/** Scan a host's TLS posture and return findings. */
export async function scanTls(host: string, options: TlsScanOptions = {}): Promise<Finding[]> {
  const port = options.port ?? 443;
  const timeoutMs = options.timeoutMs ?? 10_000;
  // Only the real network path resolves and vets; an injected probe is trusted (and offline).
  const probe = options.probe ?? networkProbe(await resolveTarget(host, options.allowPrivate ?? false));
  const result = await probe(host, port, timeoutMs);
  return analyzeTls(result, `${host}:${port}`, new Date(), { host, port });
}
