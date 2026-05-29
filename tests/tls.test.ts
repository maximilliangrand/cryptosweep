import { describe, expect, it } from "vitest";
import type { CertInfo, TlsProbe, TlsScanResult } from "../src/scanners/tls";
import { analyzeTls, normalizeCert, scanTls, signatureAlgorithmFromDer } from "../src/scanners/tls";
import type { Finding } from "../src/report";

const SHA256_RSA = Buffer.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]);
const ECDSA_SHA256 = Buffer.from([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);

function cert(overrides: Partial<CertInfo> = {}): CertInfo {
  return {
    subject: "www.example.com",
    issuer: "Example CA",
    isLeaf: true,
    keyType: "rsa",
    keyBits: 2048,
    curve: null,
    signatureAlgorithm: "sha256WithRSAEncryption",
    validFrom: "2025-01-01T00:00:00.000Z",
    validTo: "2099-01-01T00:00:00.000Z",
    ...overrides,
  };
}

function byId(findings: Finding[], id: string): Finding {
  const finding = findings.find((f) => f.id === id);
  if (!finding) throw new Error(`expected finding ${id}, got ${findings.map((f) => f.id).join(", ")}`);
  return finding;
}

const NOW = new Date("2026-01-01T00:00:00.000Z");

describe("signatureAlgorithmFromDer", () => {
  it("identifies a known signature OID embedded in DER", () => {
    const der = Buffer.concat([Buffer.from([0x30, 0x82, 0x01]), SHA256_RSA, Buffer.from([0xff])]);
    expect(signatureAlgorithmFromDer(der)).toBe("sha256WithRSAEncryption");
    expect(signatureAlgorithmFromDer(ECDSA_SHA256)).toBe("ecdsa-with-SHA256");
  });

  it("returns 'unknown' for empty or unrecognized DER", () => {
    expect(signatureAlgorithmFromDer(undefined)).toBe("unknown");
    expect(signatureAlgorithmFromDer(Buffer.from([0x00, 0x01, 0x02]))).toBe("unknown");
  });
});

describe("normalizeCert", () => {
  it("normalizes an RSA leaf certificate", () => {
    const info = normalizeCert(
      { modulus: "AA".repeat(256), exponent: "010001", bits: 2048, raw: SHA256_RSA, subject: { CN: "leaf" } },
      true,
    );
    expect(info.keyType).toBe("rsa");
    expect(info.keyBits).toBe(2048);
    expect(info.signatureAlgorithm).toBe("sha256WithRSAEncryption");
    expect(info.isLeaf).toBe(true);
  });

  it("normalizes an EC intermediate certificate", () => {
    const info = normalizeCert({ nistCurve: "P-384", bits: 384, raw: ECDSA_SHA256 }, false);
    expect(info.keyType).toBe("ec");
    expect(info.curve).toBe("P-384");
    expect(info.isLeaf).toBe(false);
  });
});

describe("analyzeTls", () => {
  it("flags an RSA leaf on TLS 1.3 without hybrid key exchange (happy path)", () => {
    const result: TlsScanResult = {
      protocol: "TLSv1.3",
      cipherName: "TLS_AES_256_GCM_SHA384",
      groupName: "X25519",
      chain: [cert()],
    };
    const findings = analyzeTls(result, "www.example.com:443", NOW);

    expect(byId(findings, "CSW-TLS-001").pq_status).toBe("vulnerable");
    expect(byId(findings, "CSW-TLS-001").title).toContain("RSA-2048");
    expect(byId(findings, "CSW-TLS-002").pq_status).toBe("vulnerable");
    expect(byId(findings, "CSW-TLS-004").title).toContain("TLSv1.3");
    const hybrid = byId(findings, "CSW-TLS-005");
    expect(hybrid.pq_status).toBe("vulnerable");
    expect(hybrid.severity).toBe("medium");
  });

  it("recognizes hybrid KEX, an ECDSA key, and an expired cert (edge case)", () => {
    const result: TlsScanResult = {
      protocol: "TLSv1.3",
      cipherName: "TLS_AES_128_GCM_SHA256",
      groupName: "X25519MLKEM768",
      chain: [
        cert({
          keyType: "ec",
          curve: "P-256",
          keyBits: 256,
          signatureAlgorithm: "ecdsa-with-SHA256",
          validTo: "2020-01-01T00:00:00.000Z",
        }),
        cert({ isLeaf: false, subject: "Example Intermediate CA" }),
      ],
    };
    const findings = analyzeTls(result, "old.example.com:443", NOW);

    expect(byId(findings, "CSW-TLS-001").title).toContain("ECDSA P-256");
    const hybrid = byId(findings, "CSW-TLS-005");
    expect(hybrid.pq_status).toBe("transitional");
    expect(hybrid.severity).toBe("info");
    const expiry = byId(findings, "CSW-TLS-007");
    expect(expiry.severity).toBe("high");
    expect(expiry.title).toContain("expired");
    expect(byId(findings, "CSW-TLS-003").title).toContain("intermediate");
  });
});

describe("scanTls", () => {
  it("uses the injected probe and stamps host:port evidence", async () => {
    const probe: TlsProbe = async (host, port) => {
      expect(host).toBe("example.com");
      expect(port).toBe(443);
      return {
        protocol: "TLSv1.2",
        cipherName: "ECDHE-RSA-AES128-GCM-SHA256",
        groupName: "P-256",
        chain: [cert()],
      };
    };
    const findings = await scanTls("example.com", { probe });
    expect(findings.some((f) => f.evidence.includes("example.com:443"))).toBe(true);
    expect(byId(findings, "CSW-TLS-004").severity).toBe("medium");
  });
});
