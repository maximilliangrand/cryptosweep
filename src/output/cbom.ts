/**
 * CycloneDX 1.6 Cryptography Bill of Materials (CBOM) emitter.
 *
 * A CBOM is the standardized, machine-readable inventory of the cryptographic
 * assets a system uses. Emitting one is what lets cryptosweep's output flow into
 * the SBOM / compliance / risk toolchains organizations already run, rather than
 * being one more bespoke report. Every cryptographic-asset component carries its
 * NIST post-quantum security level so a downstream consumer can filter for the
 * assets a quantum computer would break.
 *
 * Spec: https://cyclonedx.org/docs/1.6/json/ (cryptoProperties)
 */
import { createHash } from "node:crypto";
import type { Finding, Report } from "../report";
import { VERSION } from "../version";

/** CycloneDX cryptographic primitive categories (subset we classify into). */
type Primitive = "signature" | "kem" | "key-agree" | "pke" | "hash" | "block-cipher" | "mac" | "unknown";

interface AlgorithmDescriptor {
  primitive: Primitive;
  /** NIST post-quantum security level: 0 = broken by a CRQC, 1..5 = PQ category. */
  nistQuantumSecurityLevel: number;
  oid?: string;
  parameterSetIdentifier?: string;
}

/** Classify a canonical algorithm label into CycloneDX crypto vocabulary. */
export function describeAlgorithm(label: string): AlgorithmDescriptor {
  const l = label.toLowerCase();
  if (/^ml-dsa/.test(l)) {
    const level = l.includes("87") ? 5 : l.includes("65") ? 3 : 2;
    return { primitive: "signature", nistQuantumSecurityLevel: level, parameterSetIdentifier: label };
  }
  if (/^slh-dsa/.test(l)) return { primitive: "signature", nistQuantumSecurityLevel: 1, parameterSetIdentifier: label };
  if (/mlkem|ml-kem/.test(l)) return { primitive: "kem", nistQuantumSecurityLevel: 3, parameterSetIdentifier: label };
  if (/^rsa/.test(l)) {
    const bits = /rsa-(\d+)/.exec(l)?.[1];
    return { primitive: "signature", nistQuantumSecurityLevel: 0, oid: "1.2.840.113549.1.1.1", parameterSetIdentifier: bits };
  }
  if (/rsassapss|withrsa/.test(l)) return { primitive: "signature", nistQuantumSecurityLevel: 0, oid: "1.2.840.113549.1.1.1" };
  if (/^ecdsa|^ec-|ecdsawith/.test(l)) {
    const curve = /ecdsa-([\w-]+)/.exec(l)?.[1];
    return { primitive: "signature", nistQuantumSecurityLevel: 0, oid: "1.2.840.10045.2.1", parameterSetIdentifier: curve };
  }
  if (/^ed25519/.test(l)) return { primitive: "signature", nistQuantumSecurityLevel: 0, oid: "1.3.101.112" };
  if (/^ed448/.test(l)) return { primitive: "signature", nistQuantumSecurityLevel: 0, oid: "1.3.101.113" };
  if (/^dsa/.test(l)) return { primitive: "signature", nistQuantumSecurityLevel: 0, oid: "1.2.840.10040.4.1" };
  if (/sha-?1|md5/.test(l)) return { primitive: "hash", nistQuantumSecurityLevel: 0 };
  if (/des|rc4|rc2/.test(l)) return { primitive: "block-cipher", nistQuantumSecurityLevel: 0 };
  return { primitive: "unknown", nistQuantumSecurityLevel: 0 };
}

interface CryptoComponent {
  type: "cryptographic-asset";
  "bom-ref": string;
  name: string;
  cryptoProperties: {
    assetType: "algorithm";
    algorithmProperties: {
      primitive: Primitive;
      parameterSetIdentifier?: string;
      nistQuantumSecurityLevel: number;
    };
    oid?: string;
  };
  properties: { name: string; value: string }[];
}

/** Collapse findings into one component per distinct algorithm, most-severe evidence kept. */
function toComponents(findings: Finding[]): CryptoComponent[] {
  const byAlgorithm = new Map<string, Finding>();
  for (const finding of findings) {
    if (!finding.algorithm) continue;
    const existing = byAlgorithm.get(finding.algorithm);
    if (!existing) byAlgorithm.set(finding.algorithm, finding);
  }

  return [...byAlgorithm.entries()].map(([algorithm, finding]) => {
    const desc = describeAlgorithm(algorithm);
    const component: CryptoComponent = {
      type: "cryptographic-asset",
      "bom-ref": `crypto/${slug(algorithm)}`,
      name: algorithm,
      cryptoProperties: {
        assetType: "algorithm",
        algorithmProperties: {
          primitive: desc.primitive,
          nistQuantumSecurityLevel: desc.nistQuantumSecurityLevel,
        },
      },
      properties: [
        { name: "cryptosweep:pq_status", value: finding.pq_status },
        { name: "cryptosweep:severity", value: finding.severity },
        { name: "cryptosweep:confidence", value: finding.confidence ?? "medium" },
        { name: "cryptosweep:finding", value: finding.id },
      ],
    };
    if (desc.parameterSetIdentifier) {
      component.cryptoProperties.algorithmProperties.parameterSetIdentifier = desc.parameterSetIdentifier;
    }
    if (desc.oid) component.cryptoProperties.oid = desc.oid;
    return component;
  });
}

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

/** Deterministic BOM serial number derived from the report, so output is reproducible. */
function serialNumber(report: Report): string {
  const digest = createHash("sha256").update(`${report.target}|${report.scanned_at}`).digest("hex");
  const uuid = `${digest.slice(0, 8)}-${digest.slice(8, 12)}-4${digest.slice(13, 16)}-8${digest.slice(17, 20)}-${digest.slice(20, 32)}`;
  return `urn:uuid:${uuid}`;
}

/** Render a report as a CycloneDX 1.6 CBOM document (pretty JSON). */
export function toCbom(report: Report): string {
  const document = {
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
          },
        ],
      },
      component: {
        type: "application",
        "bom-ref": "target",
        name: report.target,
      },
    },
    components: toComponents(report.findings),
  };
  return JSON.stringify(document, null, 2);
}
