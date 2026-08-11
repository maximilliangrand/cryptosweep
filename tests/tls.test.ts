import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { CertInfo, TlsProbe, TlsScanResult } from "../src/scanners/tls";
import { analyzeTls, parseCertificate, scanTls } from "../src/scanners/tls";
import type { Finding } from "../src/report";

function readCert(name: string): Buffer {
  return readFileSync(fileURLToPath(new URL(`./fixtures/certs/${name}.pem`, import.meta.url)));
}

function cert(overrides: Partial<CertInfo> = {}): CertInfo {
  return {
    subject: "www.example.com",
    issuer: "Example CA",
    isLeaf: true,
    selfSigned: false,
    keyType: "rsa",
    keyBits: 2048,
    curve: null,
    signatureAlgorithm: "sha256WithRSAEncryption",
    signatureOid: "1.2.840.113549.1.1.11",
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

describe("parseCertificate (real fixtures)", () => {
  it("types an RSA-2048 / SHA-256 leaf from the KeyObject and ASN.1 signature", () => {
    const info = parseCertificate(readCert("rsa2048"), true);
    expect(info).not.toBeNull();
    expect(info?.keyType).toBe("rsa");
    expect(info?.keyBits).toBe(2048);
    expect(info?.signatureAlgorithm).toBe("sha256WithRSAEncryption");
    expect(info?.signatureOid).toBe("1.2.840.113549.1.1.11");
  });

  it("types an EC P-256 leaf with the friendly curve name", () => {
    const info = parseCertificate(readCert("ec-p256"), true);
    expect(info?.keyType).toBe("ec");
    expect(info?.curve).toBe("P-256");
    expect(info?.signatureAlgorithm).toBe("ecdsaWithSHA256");
  });

  it("types an Ed25519 leaf as EdDSA — the case the old scanner missed", () => {
    const info = parseCertificate(readCert("ed25519"), true);
    expect(info?.keyType).toBe("ed25519");
    expect(info?.signatureAlgorithm).toBe("Ed25519");
  });

  it("reads a SHA-1 RSA signature from the ASN.1 field", () => {
    const info = parseCertificate(readCert("rsa-sha1"), true);
    expect(info?.signatureAlgorithm).toBe("sha1WithRSAEncryption");
  });

  it("returns null for non-certificate bytes instead of throwing", () => {
    expect(parseCertificate(Buffer.from([0x00, 0x01, 0x02, 0x03]), true)).toBeNull();
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
    expect(byId(findings, "CSW-TLS-001").confidence).toBe("confirmed");
    expect(byId(findings, "CSW-TLS-002").pq_status).toBe("vulnerable");
    expect(byId(findings, "CSW-TLS-004").title).toContain("TLSv1.3");
    const hybrid = byId(findings, "CSW-TLS-005");
    expect(hybrid.pq_status).toBe("vulnerable");
    expect(hybrid.severity).toBe("medium");
  });

  it("classifies an Ed25519 leaf as quantum-vulnerable (EdDSA regression guard)", () => {
    const info = parseCertificate(readCert("ed25519"), true);
    const result: TlsScanResult = {
      protocol: "TLSv1.3",
      cipherName: "TLS_AES_128_GCM_SHA256",
      groupName: "X25519",
      chain: info ? [info] : [],
    };
    const findings = analyzeTls(result, "ed.example.com:443", NOW);
    const key = byId(findings, "CSW-TLS-001");
    expect(key.title).toContain("Ed25519");
    expect(key.pq_status).toBe("vulnerable");
    // Classically sound: a migration item (medium), not a live break.
    expect(key.severity).toBe("medium");
    expect(key.confidence).toBe("confirmed");
  });

  it("grades classical key strength separately from the quantum verdict", () => {
    const grade = (overrides: Partial<CertInfo>): Finding =>
      byId(
        analyzeTls(
          { protocol: "TLSv1.3", cipherName: null, groupName: "X25519", chain: [cert(overrides)] },
          "graded.example.com:443",
          NOW,
        ),
        "CSW-TLS-001",
      );

    // Sound today, broken by a CRQC: a plan-ahead item, so a `--fail-on high`
    // gate is not red for every certificate on the public internet.
    expect(grade({ keyBits: 4096 }).severity).toBe("medium");
    expect(grade({ keyType: "ec", curve: "P-256", keyBits: null }).severity).toBe("medium");
    // Below the SP 800-131A floor: broken classically, today.
    expect(grade({ keyBits: 1024 }).severity).toBe("high");
    expect(grade({ keyBits: 512 }).severity).toBe("critical");
    expect(grade({ keyType: "ec", curve: "P-192", keyBits: null }).severity).toBe("high");
    // The quantum verdict is unchanged in every case.
    expect(grade({ keyBits: 4096 }).pq_status).toBe("vulnerable");
    expect(grade({ keyBits: 1024 }).recommendation).toMatch(/SP 800-131A/);
  });

  it("rates an MD5-signed certificate critical instead of burying it as info", () => {
    const info = parseCertificate(readCert("rsa-md5"), true);
    expect(info?.signatureAlgorithm).toBe("md5WithRSAEncryption");
    const findings = analyzeTls(
      { protocol: "TLSv1.3", cipherName: null, groupName: "X25519", chain: info ? [info] : [] },
      "md5.example.com:443",
      NOW,
    );
    const sig = byId(findings, "CSW-TLS-002");
    expect(sig.severity).toBe("critical");
    expect(sig.confidence).toBe("confirmed");
    expect(sig.pq_status).toBe("vulnerable");
  });

  it("treats an unrecognized signature OID as a review item, not a clean bill of health", () => {
    const findings = analyzeTls(
      { protocol: "TLSv1.3", cipherName: null, groupName: "X25519", chain: [cert({ signatureAlgorithm: "unknown", signatureOid: "9.9.9.9" })] },
      "odd.example.com:443",
      NOW,
    );
    const sig = byId(findings, "CSW-TLS-002");
    expect(sig.severity).toBe("medium");
    expect(sig.confidence).toBe("low");
  });

  it("rates a SHA-1 signature high with a classical-break note (dead-branch regression guard)", () => {
    const findings = analyzeTls(
      { protocol: "TLSv1.3", cipherName: null, groupName: "X25519", chain: [cert({ signatureAlgorithm: "sha1WithRSAEncryption" })] },
      "sha1.example.com:443",
      NOW,
    );
    const sig = byId(findings, "CSW-TLS-002");
    expect(sig.severity).toBe("high");
    expect(sig.confidence).toBe("confirmed");
    expect(sig.recommendation).toMatch(/SHA-1/);
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
          signatureAlgorithm: "ecdsaWithSHA256",
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

  it("reports unknown (not vulnerable) when the group cannot be determined", () => {
    const findings = analyzeTls(
      { protocol: "TLSv1.3", cipherName: null, groupName: null, chain: [cert()] },
      "x.example.com:443",
      NOW,
    );
    const hybrid = byId(findings, "CSW-TLS-005");
    expect(hybrid.pq_status).toBe("unknown");
    expect(hybrid.confidence).toBe("low");
  });

  it("trusts the active hybrid probe over an unobservable group name", () => {
    const supported = byId(
      analyzeTls(
        { protocol: "TLSv1.3", cipherName: null, groupName: null, hybridKex: "supported", chain: [cert()] },
        "hy.example.com:443",
        NOW,
      ),
      "CSW-TLS-005",
    );
    expect(supported.pq_status).toBe("transitional");
    expect(supported.confidence).toBe("confirmed");
    expect(supported.title).toContain("supports hybrid");

    const unsupported = byId(
      analyzeTls(
        { protocol: "TLSv1.3", cipherName: null, groupName: null, hybridKex: "unsupported", chain: [cert()] },
        "cl.example.com:443",
        NOW,
      ),
      "CSW-TLS-005",
    );
    expect(unsupported.pq_status).toBe("vulnerable");
    expect(unsupported.severity).toBe("medium");
    expect(unsupported.confidence).toBe("confirmed");
  });
});

describe("certificate chain finding", () => {
  const leaf = cert({ subject: "www.example.com", issuer: "WE1" });
  const intermediate = cert({ isLeaf: false, subject: "WE1", issuer: "GTS Root R4", keyType: "ec", curve: "P-256", keyBits: null });
  const root = cert({ isLeaf: false, subject: "GTS Root R4", issuer: "GTS Root R4", selfSigned: true });

  function chainFinding(chain: CertInfo[]): Finding | undefined {
    return analyzeTls({ protocol: "TLSv1.3", cipherName: null, groupName: "X25519", chain }, "www.example.com:443", NOW).find(
      (f) => f.id === "CSW-TLS-003",
    );
  }

  it("names the intermediates' subjects, not their issuers", () => {
    const finding = chainFinding([leaf, intermediate, root]);
    expect(finding?.evidence).toContain("WE1");
    // The old evidence printed issuers, so the only real intermediate (WE1) was
    // missing and the self-signed root's own name appeared twice.
    expect(finding?.evidence).not.toContain("GTS Root R4");
    expect(finding?.evidence).not.toMatch(/(GTS Root R4).*\1/);
  });

  it("excludes the self-signed trust anchor Node walks in from the local store", () => {
    expect(chainFinding([leaf, intermediate, root])?.title).toContain("1 intermediate(s)");
    // A leaf plus only a locally-supplied root is not a chain with intermediates.
    expect(chainFinding([leaf, root])).toBeUndefined();
  });

  it("derives the classical verdict from the parsed intermediate key types", () => {
    const parsed = chainFinding([leaf, intermediate]);
    expect(parsed?.pq_status).toBe("vulnerable");
    expect(parsed?.confidence).toBe("confirmed");

    const opaque = chainFinding([leaf, cert({ isLeaf: false, subject: "Opaque CA", keyType: "unknown", keyBits: null })]);
    expect(opaque?.pq_status).toBe("unknown");
    expect(opaque?.confidence).toBe("high");
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

  it("stamps host/port on every network finding so SARIF can anchor them", async () => {
    const probe: TlsProbe = async () => ({
      protocol: "TLSv1.3",
      cipherName: "TLS_AES_256_GCM_SHA384",
      groupName: "X25519",
      chain: [cert()],
    });
    const findings = await scanTls("example.com", { probe, port: 8443 });
    expect(findings.length).toBeGreaterThan(0);
    for (const finding of findings) {
      expect(finding.location?.host, finding.id).toBe("example.com");
      expect(finding.location?.port, finding.id).toBe(8443);
    }
  });
});
