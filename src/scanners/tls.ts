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
import { REFS, curveFriendlyName, isClassicallyWeakKey, isQuantumVulnerableKey, keyAlgorithmLabel, keyPosture } from "../crypto";
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
    selfSigned: x509.subject === x509.issuer,
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
    return {
      severity: "info",
      pq_status: "safe",
      confidence: "confirmed",
      references: [REFS.fips204, REFS.fips205],
      recommendation: "Post-quantum signature already in use, keep it and track CA/ecosystem interop.",
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

/**
 * Assess the certificates above the leaf.
 *
 * Two things must be right here or the finding is fiction. First, Node's
 * `getPeerCertificate(true)` keeps walking `issuerCertificate` into the local
 * trust store, so the last entry is usually a root the server never sent; roots
 * are self-signed, so we drop them and count only real intermediates. Second,
 * the verdict is read from each intermediate's parsed key type, not asserted.
 */
function evaluateChain(chain: CertInfo[]): Finding | null {
  const intermediates = chain.slice(1).filter((c) => !c.selfSigned);
  if (intermediates.length === 0) return null;

  const classical = intermediates.filter((c) => isQuantumVulnerableKey(c.keyType));
  const unparsed = intermediates.length - classical.length;
  const posture =
    unparsed === 0
      ? "using classical crypto"
      : `${classical.length} of ${intermediates.length} using classical crypto, ${unparsed} of unrecognized key type`;

  return {
    id: "CSW-TLS-003",
    ruleId: "tls/chain-classical",
    severity: "medium",
    category: "tls",
    title: `Certificate chain has ${intermediates.length} intermediate(s) ${posture}`,
    evidence: intermediates.map((c) => `${c.subject} (${keyDescription(c)})`).join(" → "),
    pq_status: classical.length > 0 ? "vulnerable" : "unknown",
    confidence: unparsed === 0 ? "confirmed" : "high",
    references: [REFS.fips204, REFS.cnsa2],
    recommendation: "The whole chain must migrate; classical intermediates remain quantum-vulnerable.",
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
    const classicallyWeak = isClassicallyWeakKey(leaf.keyType, leaf.keyBits, leaf.curve);
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
      recommendation: classicallyWeak
        ? "Below the SP 800-131A minimum (RSA/DSA ≥ 2048 bits, ECC ≥ 224-bit curve): this key is at risk from classical attack today. Re-key now, then plan the post-quantum migration."
        : posture.pq_status === "vulnerable"
          ? "Classically sound but pre-quantum. Plan migration to a post-quantum / hybrid certificate (ML-DSA) as CA support arrives."
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

  const chainFinding = evaluateChain(result.chain);
  if (chainFinding) findings.push(chainFinding);

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
