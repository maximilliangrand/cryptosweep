/**
 * TLS posture scanner.
 *
 * Connects to a host on 443 (via an injectable probe so tests stay offline),
 * inspects the certificate chain and negotiated parameters, and flags
 * classical primitives that a cryptographically-relevant quantum computer
 * would break (RSA, ECDSA/EdDSA, non-hybrid key exchange).
 */
import { connect as tlsConnect } from "node:tls";
import type { DetailedPeerCertificate } from "node:tls";
import type { Finding, PqStatus, Severity } from "../report";

export type KeyType = "rsa" | "ec" | "ed25519" | "ed448" | "unknown";

export interface CertInfo {
  subject: string;
  issuer: string;
  isLeaf: boolean;
  keyType: KeyType;
  keyBits: number | null;
  curve: string | null;
  signatureAlgorithm: string;
  validFrom: string;
  validTo: string;
}

export interface TlsScanResult {
  protocol: string | null;
  cipherName: string | null;
  /** Negotiated key-exchange group, e.g. "X25519", "P-256", "X25519MLKEM768". */
  groupName: string | null;
  chain: CertInfo[];
}

export type TlsProbe = (host: string, port: number, timeoutMs: number) => Promise<TlsScanResult>;

export interface TlsScanOptions {
  port?: number;
  timeoutMs?: number;
  probe?: TlsProbe;
}

/** Minimal structural view of Node's PeerCertificate — keeps the analyzer testable. */
export interface RawCertificate {
  subject?: Record<string, string> | string;
  issuer?: Record<string, string> | string;
  valid_from?: string;
  valid_to?: string;
  modulus?: string;
  exponent?: string;
  bits?: number;
  nistCurve?: string;
  asn1Curve?: string;
  pubkey?: Buffer;
  raw?: Buffer;
}

const SIGNATURE_OIDS: ReadonlyArray<{ name: string; bytes: number[] }> = [
  { name: "sha256WithRSAEncryption", bytes: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b] },
  { name: "sha384WithRSAEncryption", bytes: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c] },
  { name: "sha512WithRSAEncryption", bytes: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d] },
  { name: "sha1WithRSAEncryption", bytes: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05] },
  { name: "rsassaPss", bytes: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a] },
  { name: "ecdsa-with-SHA256", bytes: [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02] },
  { name: "ecdsa-with-SHA384", bytes: [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03] },
  { name: "ecdsa-with-SHA512", bytes: [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04] },
  { name: "Ed25519", bytes: [0x2b, 0x65, 0x70] },
  { name: "Ed448", bytes: [0x2b, 0x65, 0x71] },
];

const HYBRID_KEX = /MLKEM|KYBER/i;

/** Extract a signature algorithm name by matching known OID byte sequences in the cert DER. */
export function signatureAlgorithmFromDer(raw: Buffer | undefined): string {
  if (!raw || raw.length === 0) return "unknown";
  for (const oid of SIGNATURE_OIDS) {
    if (raw.indexOf(Buffer.from(oid.bytes)) !== -1) return oid.name;
  }
  return "unknown";
}

function commonName(field: Record<string, string> | string | undefined): string {
  if (!field) return "unknown";
  if (typeof field === "string") return field;
  return field.CN ?? field.O ?? "unknown";
}

function toIso(value: string | undefined): string {
  if (!value) return "unknown";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toISOString();
}

/** Normalize a raw peer certificate into the scanner-facing shape. */
export function normalizeCert(raw: RawCertificate, isLeaf: boolean): CertInfo {
  let keyType: KeyType = "unknown";
  let keyBits: number | null = raw.bits ?? null;
  let curve: string | null = null;

  if (raw.modulus && raw.exponent) {
    keyType = "rsa";
    keyBits = raw.bits ?? raw.modulus.length * 4;
  } else if (raw.nistCurve || raw.asn1Curve) {
    keyType = "ec";
    curve = raw.nistCurve ?? raw.asn1Curve ?? null;
  }

  return {
    subject: commonName(raw.subject),
    issuer: commonName(raw.issuer),
    isLeaf,
    keyType,
    keyBits,
    curve,
    signatureAlgorithm: signatureAlgorithmFromDer(raw.raw),
    validFrom: toIso(raw.valid_from),
    validTo: toIso(raw.valid_to),
  };
}

function keyDescription(cert: CertInfo): string {
  if (cert.keyType === "rsa") return `RSA-${cert.keyBits ?? "?"}`;
  if (cert.keyType === "ec") return `ECDSA ${cert.curve ?? "(unknown curve)"}`;
  if (cert.keyType === "ed25519") return "Ed25519";
  if (cert.keyType === "ed448") return "Ed448";
  return "unknown key type";
}

function keyPqStatus(keyType: KeyType): { pq: PqStatus; severity: Severity } {
  // RSA, ECDSA and EdDSA are all broken by Shor's algorithm.
  if (keyType === "unknown") return { pq: "unknown", severity: "info" };
  return { pq: "vulnerable", severity: "high" };
}

function evaluateProtocol(protocol: string | null, evidence: string): Finding | null {
  if (!protocol) return null;
  if (protocol === "TLSv1.3" || protocol === "TLSv1.2") {
    return {
      id: "CSW-TLS-004",
      severity: protocol === "TLSv1.3" ? "info" : "medium",
      category: "tls",
      title: `Negotiated ${protocol}`,
      evidence,
      pq_status: "transitional",
      recommendation:
        protocol === "TLSv1.3"
          ? "TLS 1.3 is required for hybrid post-quantum key exchange — keep it enabled."
          : "Upgrade to TLS 1.3 to enable hybrid post-quantum key exchange (X25519MLKEM768).",
    };
  }
  return {
    id: "CSW-TLS-004",
    severity: "high",
    category: "tls",
    title: `Obsolete protocol negotiated (${protocol})`,
    evidence,
    pq_status: "vulnerable",
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
      severity: "high",
      category: "tls",
      title: "Leaf certificate has expired",
      evidence: `${evidence} valid_to=${cert.validTo}`,
      pq_status: "unknown",
      recommendation: "Renew the certificate; an expired chain blocks any crypto-agility rollout.",
    };
  }
  const thirtyDays = 30 * 24 * 60 * 60 * 1000;
  if (msLeft < thirtyDays) {
    return {
      id: "CSW-TLS-007",
      severity: "low",
      category: "tls",
      title: "Leaf certificate expires within 30 days",
      evidence: `${evidence} valid_to=${cert.validTo}`,
      pq_status: "unknown",
      recommendation: "Schedule renewal; pair it with a move to crypto-agile certificate tooling.",
    };
  }
  return null;
}

function evaluateHybridKex(result: TlsScanResult, evidence: string): Finding {
  const negotiated = `${result.groupName ?? ""} ${result.cipherName ?? ""}`.trim();
  if (HYBRID_KEX.test(negotiated)) {
    return {
      id: "CSW-TLS-005",
      severity: "info",
      category: "tls",
      title: `Hybrid post-quantum key exchange negotiated (${result.groupName ?? "hybrid"})`,
      evidence: `${evidence} ${negotiated}`,
      pq_status: "transitional",
      recommendation: "Hybrid KEX in place — track migration to standalone ML-KEM once mandated.",
    };
  }
  return {
    id: "CSW-TLS-005",
    severity: "medium",
    category: "tls",
    title: "No hybrid post-quantum key exchange negotiated",
    evidence: result.groupName ? `${evidence} group=${result.groupName}` : evidence,
    pq_status: "vulnerable",
    recommendation:
      "Enable X25519MLKEM768 so session keys resist harvest-now-decrypt-later attacks.",
  };
}

/** Analyze a completed handshake and return findings. Pure — drives the tests. */
export function analyzeTls(result: TlsScanResult, target = "tls", now: Date = new Date()): Finding[] {
  const findings: Finding[] = [];
  const leaf = result.chain[0];

  if (!leaf) {
    findings.push({
      id: "CSW-TLS-000",
      severity: "info",
      category: "tls",
      title: "No leaf certificate could be read",
      evidence: target,
      pq_status: "unknown",
      recommendation: "Verify the host serves a certificate on the scanned port.",
    });
  } else {
    const subjectEvidence = `${target} (${leaf.subject})`;
    const { pq, severity } = keyPqStatus(leaf.keyType);
    findings.push({
      id: "CSW-TLS-001",
      severity,
      category: "tls",
      title: `Leaf public key: ${keyDescription(leaf)}`,
      evidence: subjectEvidence,
      pq_status: pq,
      recommendation:
        pq === "vulnerable"
          ? "Plan migration to a post-quantum / hybrid certificate (ML-DSA) as CA support arrives."
          : "Confirm the key type and document it in the crypto inventory.",
    });

    const sigVulnerable = leaf.signatureAlgorithm !== "unknown";
    findings.push({
      id: "CSW-TLS-002",
      severity: leaf.signatureAlgorithm.includes("SHA1") ? "high" : sigVulnerable ? "high" : "info",
      category: "tls",
      title: `Leaf signature algorithm: ${leaf.signatureAlgorithm}`,
      evidence: subjectEvidence,
      pq_status: sigVulnerable ? "vulnerable" : "unknown",
      recommendation: sigVulnerable
        ? "Classical signature; move to ML-DSA / hybrid certificates when available."
        : "Signature algorithm could not be identified from the DER — verify manually.",
    });

    const validity = evaluateValidity(leaf, target, now);
    if (validity) findings.push(validity);
  }

  if (result.chain.length > 1) {
    findings.push({
      id: "CSW-TLS-003",
      severity: "medium",
      category: "tls",
      title: `Certificate chain has ${result.chain.length - 1} intermediate(s) using classical crypto`,
      evidence: result.chain
        .slice(1)
        .map((c) => c.issuer)
        .join(" → "),
      pq_status: "vulnerable",
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
    chain.push(
      normalizeCert(
        {
          subject: cert.subject as unknown as Record<string, string>,
          issuer: cert.issuer as unknown as Record<string, string>,
          valid_from: cert.valid_from,
          valid_to: cert.valid_to,
          modulus: cert.modulus,
          exponent: cert.exponent,
          bits: cert.bits,
          nistCurve: cert.nistCurve,
          asn1Curve: cert.asn1Curve,
          pubkey: cert.pubkey,
          raw: cert.raw,
        },
        isLeaf,
      ),
    );
    isLeaf = false;
    const next: DetailedPeerCertificate | undefined = cert.issuerCertificate;
    if (!next || next.fingerprint256 === cert.fingerprint256) break;
    cert = next;
  }
  return chain;
}

const defaultProbe: TlsProbe = (host, port, timeoutMs) =>
  new Promise<TlsScanResult>((resolve, reject) => {
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
          const result: TlsScanResult = {
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

/** Scan a host's TLS posture and return findings. */
export async function scanTls(host: string, options: TlsScanOptions = {}): Promise<Finding[]> {
  const port = options.port ?? 443;
  const timeoutMs = options.timeoutMs ?? 10_000;
  const probe = options.probe ?? defaultProbe;
  const result = await probe(host, port, timeoutMs);
  return analyzeTls(result, `${host}:${port}`);
}
