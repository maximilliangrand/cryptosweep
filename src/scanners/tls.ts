/**
 * TLS posture scanner.
 *
 * Connects to a host (via an injectable probe so tests stay offline), then
 * classifies the certificate chain and negotiated parameters. Every leaf key is
 * typed from a parsed `KeyObject` and every signature algorithm from the
 * certificate's actual ASN.1 `signatureAlgorithm` field, never from guessing at
 * bytes, so a "vulnerable" verdict is defensible to an auditor.
 */
import { connect as tlsConnect } from "node:tls";
import type { DetailedPeerCertificate } from "node:tls";
import { isIP } from "node:net";
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
import { assertTargetAllowed } from "../net-guard";
import type { Confidence, Finding, Location, PqStatus, Reference, Severity } from "../report";

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
 * Whether the server will negotiate a hybrid post-quantum key-exchange group.
 * Determined by an active capability probe, because Node does not expose the
 * negotiated group for TLS 1.3 sessions.
 */
export type HybridSupport = "supported" | "unsupported" | "unknown";

export interface TlsScanResult {
  protocol: string | null;
  cipherName: string | null;
  /** Negotiated key-exchange group, e.g. "X25519", "P-256", "X25519MLKEM768". */
  groupName: string | null;
  /** Result of actively probing for hybrid PQ key exchange (X25519MLKEM768). */
  hybridKex?: HybridSupport;
  chain: CertInfo[];
}

/** The IANA/OpenSSL name of the standardized hybrid group we probe for. */
const HYBRID_GROUP = "X25519MLKEM768";

export type TlsProbe = (host: string, port: number, timeoutMs: number) => Promise<TlsScanResult>;

export interface TlsScanOptions {
  port?: number;
  timeoutMs?: number;
  probe?: TlsProbe;
  /** Allow scanning non-public addresses (localhost, RFC 1918). Off by default. */
  allowPrivate?: boolean;
}

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
        references: sig.references,
        recommendation: sig.recommendation,
      },
    ];
  });
}

function evaluateProtocol(protocol: string | null, evidence: string): Finding | null {
  if (!protocol) return null;
  if (protocol === "TLSv1.3" || protocol === "TLSv1.2") {
    return {
      id: "CSW-TLS-004",
      ruleId: "tls/negotiated-protocol",
      severity: protocol === "TLSv1.3" ? "info" : "medium",
      category: "tls",
      title: `Negotiated ${protocol}`,
      evidence,
      pq_status: "transitional",
      confidence: "confirmed",
      references: [REFS.hybridKex],
      recommendation:
        protocol === "TLSv1.3"
          ? "TLS 1.3 is required for hybrid post-quantum key exchange, keep it enabled."
          : "Upgrade to TLS 1.3 to enable hybrid post-quantum key exchange (X25519MLKEM768).",
    };
  }
  return {
    id: "CSW-TLS-004",
    ruleId: "tls/negotiated-protocol",
    severity: "high",
    category: "tls",
    title: `Obsolete protocol negotiated (${protocol})`,
    evidence,
    pq_status: "vulnerable",
    confidence: "confirmed",
    references: [REFS.hybridKex],
    recommendation: "Disable TLS < 1.2 and adopt TLS 1.3 to support post-quantum key exchange.",
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

function evaluateHybridKex(result: TlsScanResult, evidence: string): Finding {
  const base = { id: "CSW-TLS-005", ruleId: "tls/hybrid-kex", category: "tls" as const };

  // Preferred signal: the active capability probe.
  if (result.hybridKex === "supported") {
    return {
      ...base,
      severity: "info",
      title: `Server supports hybrid post-quantum key exchange (${HYBRID_GROUP})`,
      evidence: `${evidence} group=${HYBRID_GROUP}`,
      pq_status: "transitional",
      confidence: "confirmed",
      algorithm: HYBRID_GROUP,
      references: [REFS.hybridKex, REFS.fips203],
      recommendation:
        "Hybrid KEX available, keep it enabled and track migration to standalone ML-KEM once mandated.",
    };
  }
  if (result.hybridKex === "unsupported") {
    return {
      ...base,
      severity: "medium",
      title: "Server does not support hybrid post-quantum key exchange",
      evidence: `${evidence} group=${HYBRID_GROUP}`,
      pq_status: "vulnerable",
      confidence: "confirmed",
      references: [REFS.hybridKex, REFS.fips203],
      recommendation:
        "Enable X25519MLKEM768 so session keys resist harvest-now-decrypt-later attacks.",
    };
  }

  // Fallback: a negotiated group name, when one was observable (TLS 1.2 / injected).
  const negotiated = `${result.groupName ?? ""} ${result.cipherName ?? ""}`.trim();
  if (HYBRID_KEX.test(negotiated)) {
    return {
      ...base,
      severity: "info",
      title: `Hybrid post-quantum key exchange negotiated (${result.groupName ?? "hybrid"})`,
      evidence: `${evidence} ${negotiated}`,
      pq_status: "transitional",
      confidence: "high",
      algorithm: result.groupName ?? "hybrid-kex",
      references: [REFS.hybridKex, REFS.fips203],
      recommendation: "Hybrid KEX in place, track migration to standalone ML-KEM once mandated.",
    };
  }
  if (result.groupName) {
    return {
      ...base,
      severity: "medium",
      title: "No hybrid post-quantum key exchange negotiated",
      evidence: `${evidence} group=${result.groupName}`,
      pq_status: "vulnerable",
      confidence: "high",
      algorithm: result.groupName,
      references: [REFS.hybridKex, REFS.fips203],
      recommendation:
        "Enable X25519MLKEM768 so session keys resist harvest-now-decrypt-later attacks.",
    };
  }
  return {
    ...base,
    severity: "info",
    title: "Hybrid post-quantum key-exchange support could not be determined",
    evidence,
    pq_status: "unknown",
    confidence: "low",
    references: [REFS.hybridKex],
    recommendation:
      "Could not determine hybrid support; confirm whether X25519MLKEM768 is enabled server-side.",
  };
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
      references: sig.references,
      recommendation: sig.recommendation,
    });

    const validity = evaluateValidity(leaf, target, now);
    if (validity) findings.push(validity);
  }

  const chainFinding = evaluateChain(result.chain);
  if (chainFinding) findings.push(chainFinding);
  findings.push(...evaluateIntermediateSignatures(result.chain, target));

  const protocolFinding = evaluateProtocol(result.protocol, target);
  if (protocolFinding) findings.push(protocolFinding);
  findings.push(evaluateHybridKex(result, target));

  // Network findings have no file path; the host/port IS their location, and
  // SARIF consumers drop results that carry none.
  if (location) for (const finding of findings) finding.location = { ...location };

  return findings;
}

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

/** Perform the primary handshake and read the certificate chain and parameters. */
function handshake(host: string, port: number, timeoutMs: number): Promise<Omit<TlsScanResult, "hybridKex">> {
  return new Promise((resolve, reject) => {
    const socket = tlsConnect(
      {
        host,
        port,
        // SNI must be a hostname; Node rejects an IP literal as servername.
        ...(isIP(host) ? {} : { servername: host }),
        rejectUnauthorized: false,
        ALPNProtocols: ["h2", "http/1.1"],
      },
      () => {
        try {
          const detailed = socket.getPeerCertificate(true);
          const cipher = socket.getCipher();
          const ephemeral = socket.getEphemeralKeyInfo();
          const groupName =
            ephemeral && typeof ephemeral === "object" && "name" in ephemeral
              ? ((ephemeral as { name?: string }).name ?? null)
              : null;
          const result: Omit<TlsScanResult, "hybridKex"> = {
            protocol: socket.getProtocol(),
            cipherName: cipher?.name ?? null,
            groupName,
            chain: collectChain(detailed),
          };
          socket.end();
          resolve(result);
        } catch (err) {
          socket.destroy();
          reject(err instanceof Error ? err : new Error(String(err)));
        }
      },
    );
    socket.once("error", reject);
    socket.setTimeout(timeoutMs, () => {
      socket.destroy(new Error(`TLS handshake to ${host}:${port} timed out after ${timeoutMs}ms`));
    });
  });
}

/**
 * Actively probe whether the server will negotiate the standardized hybrid
 * post-quantum group. We attempt a handshake restricted to X25519MLKEM768: a
 * clean completion proves support; a TLS-level rejection proves the server
 * refused it; a network error (or an OpenSSL that doesn't know the group) is
 * inconclusive. We never conclude "unsupported" from an ambiguous failure.
 */
function probeHybridSupport(host: string, port: number, timeoutMs: number): Promise<HybridSupport> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (value: HybridSupport): void => {
      if (!settled) {
        settled = true;
        resolve(value);
      }
    };
    let socket: ReturnType<typeof tlsConnect>;
    try {
      socket = tlsConnect(
        {
          host,
          port,
          ...(isIP(host) ? {} : { servername: host }),
          rejectUnauthorized: false,
          ecdhCurve: HYBRID_GROUP,
        },
        () => {
          done("supported");
          socket.end();
        },
      );
    } catch {
      // Local OpenSSL does not know the group name, cannot probe.
      done("unknown");
      return;
    }
    socket.once("error", (err: NodeJS.ErrnoException) => {
      const code = err.code ?? "";
      const message = err.message ?? String(err);
      if (/^(ECONNREFUSED|ENOTFOUND|EAI_AGAIN|ETIMEDOUT|ECONNRESET|EHOSTUNREACH|ENETUNREACH|EPIPE)$/.test(code)) {
        done("unknown"); // transport-level problem, inconclusive
      } else if (/ERR_SSL|handshake|alert|curve|group|no protocols|version|unsupported/i.test(`${code} ${message}`)) {
        done("unsupported"); // server actively refused the hybrid group
      } else {
        done("unknown");
      }
      socket.destroy();
    });
    socket.setTimeout(timeoutMs, () => {
      done("unknown");
      socket.destroy();
    });
  });
}

const defaultProbe: TlsProbe = async (host, port, timeoutMs) => {
  const [base, hybridKex] = await Promise.all([
    handshake(host, port, timeoutMs),
    probeHybridSupport(host, port, Math.min(timeoutMs, 8000)),
  ]);
  return { ...base, hybridKex };
};

/** Scan a host's TLS posture and return findings. */
export async function scanTls(host: string, options: TlsScanOptions = {}): Promise<Finding[]> {
  const port = options.port ?? 443;
  const timeoutMs = options.timeoutMs ?? 10_000;
  const probe = options.probe ?? defaultProbe;
  // Only guard the real network path; an injected probe is trusted (and offline).
  if (!options.probe) await assertTargetAllowed(host, options.allowPrivate);
  const result = await probe(host, port, timeoutMs);
  return analyzeTls(result, `${host}:${port}`, new Date(), { host, port });
}
