/**
 * TLS posture scanner.
 *
 * Connects to a host (via an injectable probe so tests stay offline), then
 * classifies the certificate chain and negotiated parameters. Every leaf key is
 * typed from a parsed `KeyObject` and every signature algorithm from the
 * certificate's actual ASN.1 `signatureAlgorithm` field — never from guessing at
 * bytes — so a "vulnerable" verdict is defensible to an auditor.
 */
import { connect as tlsConnect } from "node:tls";
import type { DetailedPeerCertificate } from "node:tls";
import { X509Certificate } from "node:crypto";
import { certificateSignatureOid, signatureAlgorithmName } from "../asn1";
import { REFS, curveFriendlyName, keyAlgorithmLabel, keyPosture } from "../crypto";
import type { KeyType } from "../crypto";
import type { Confidence, Finding, PqStatus, Reference, Severity } from "../report";

export type { KeyType } from "../crypto";

export interface CertInfo {
  subject: string;
  issuer: string;
  isLeaf: boolean;
  keyType: KeyType;
  keyBits: number | null;
  curve: string | null;
  /** Friendly signature-algorithm name (e.g. "sha256WithRSAEncryption"), or "unknown". */
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

const RECOGNIZED_KEY_TYPES: ReadonlySet<string> = new Set([
  "rsa",
  "rsa-pss",
  "dsa",
  "ec",
  "ed25519",
  "ed448",
]);

/**
 * Parse a DER certificate into the scanner-facing shape using Node's X.509 and
 * KeyObject APIs plus our ASN.1 signature reader. Returns null if the bytes are
 * not a parseable certificate (a hostile or truncated chain never throws).
 */
export function parseCertificate(der: Buffer, isLeaf: boolean): CertInfo | null {
  let x509: X509Certificate;
  try {
    x509 = new X509Certificate(der);
  } catch {
    return null;
  }

  const reportedType = x509.publicKey.asymmetricKeyType ?? "unknown";
  const keyType: KeyType = RECOGNIZED_KEY_TYPES.has(reportedType) ? (reportedType as KeyType) : "unknown";
  const details = x509.publicKey.asymmetricKeyDetails ?? {};
  const modulusLength = typeof details.modulusLength === "number" ? details.modulusLength : null;
  const keyBits = modulusLength ?? fixedKeyBits(keyType);
  const curve = curveFriendlyName(details.namedCurve ?? null);

  const signatureOid = certificateSignatureOid(x509.raw);

  return {
    subject: commonName(x509.subject),
    issuer: commonName(x509.issuer),
    isLeaf,
    keyType,
    keyBits,
    curve,
    signatureAlgorithm: signatureAlgorithmName(signatureOid) ?? "unknown",
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
    return {
      severity: "info",
      pq_status: "unknown",
      confidence: "low",
      references: [],
      recommendation: "Signature algorithm OID was not recognized — verify the certificate manually.",
    };
  }
  if (/^ML-DSA|^SLH-DSA/i.test(name)) {
    return {
      severity: "info",
      pq_status: "safe",
      confidence: "confirmed",
      references: [REFS.fips204, REFS.fips205],
      recommendation: "Post-quantum signature already in use — keep it and track CA/ecosystem interop.",
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
    severity: "high",
    pq_status: "vulnerable",
    confidence: "confirmed",
    references: [REFS.fips204, REFS.cnsa2],
    recommendation: "Classical signature; move to ML-DSA / hybrid certificates when CA support arrives.",
  };
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
          ? "TLS 1.3 is required for hybrid post-quantum key exchange — keep it enabled."
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
        "Hybrid KEX available — keep it enabled and track migration to standalone ML-KEM once mandated.",
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
      recommendation: "Hybrid KEX in place — track migration to standalone ML-KEM once mandated.",
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

/** Analyze a completed handshake and return findings. Pure — drives the tests. */
export function analyzeTls(result: TlsScanResult, target = "tls", now: Date = new Date()): Finding[] {
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
    const posture = keyPosture(leaf.keyType);
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
      recommendation:
        posture.pq_status === "vulnerable"
          ? "Plan migration to a post-quantum / hybrid certificate (ML-DSA) as CA support arrives."
          : "Confirm the key type and document it in the crypto inventory.",
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

  if (result.chain.length > 1) {
    findings.push({
      id: "CSW-TLS-003",
      ruleId: "tls/chain-classical",
      severity: "medium",
      category: "tls",
      title: `Certificate chain has ${result.chain.length - 1} intermediate(s) using classical crypto`,
      evidence: result.chain
        .slice(1)
        .map((c) => c.issuer)
        .join(" → "),
      pq_status: "vulnerable",
      confidence: "high",
      references: [REFS.fips204, REFS.cnsa2],
      recommendation:
        "The whole chain must migrate; classical intermediates remain quantum-vulnerable.",
    });
  }

  const protocolFinding = evaluateProtocol(result.protocol, target);
  if (protocolFinding) findings.push(protocolFinding);
  findings.push(evaluateHybridKex(result, target));

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
        servername: host,
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
        { host, port, servername: host, rejectUnauthorized: false, ecdhCurve: HYBRID_GROUP },
        () => {
          done("supported");
          socket.end();
        },
      );
    } catch {
      // Local OpenSSL does not know the group name — cannot probe.
      done("unknown");
      return;
    }
    socket.once("error", (err: NodeJS.ErrnoException) => {
      const code = err.code ?? "";
      const message = err.message ?? String(err);
      if (/^(ECONNREFUSED|ENOTFOUND|EAI_AGAIN|ETIMEDOUT|ECONNRESET|EHOSTUNREACH|ENETUNREACH|EPIPE)$/.test(code)) {
        done("unknown"); // transport-level problem — inconclusive
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
  const result = await probe(host, port, timeoutMs);
  return analyzeTls(result, `${host}:${port}`);
}
