import { describe, expect, it } from "vitest";
import type { CertInfo, GroupProbeResult, TlsScanResult } from "../src/scanners/tls";
import { analyzeTls } from "../src/scanners/tls";
import type { Finding } from "../src/report";

const NOW = new Date("2026-01-01T00:00:00.000Z");

const LEAF: CertInfo = {
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
};

const ALL_GROUPS = ["X25519MLKEM768", "SecP256r1MLKEM768", "MLKEM768", "SecP384r1MLKEM1024", "MLKEM1024"];

function probes(accepted: string[], outcomeForRest: GroupProbeResult["outcome"] = "rejected"): GroupProbeResult[] {
  return ALL_GROUPS.map((group) => ({ group, outcome: accepted.includes(group) ? "accepted" : outcomeForRest }));
}

function analyze(overrides: Partial<TlsScanResult>): Finding[] {
  return analyzeTls(
    { protocol: "TLSv1.3", cipherName: "TLS_AES_256_GCM_SHA384", groupName: "X25519", chain: [LEAF], ...overrides },
    "kex.example.com:443",
    NOW,
  );
}

function kex(overrides: Partial<TlsScanResult>): Finding {
  const finding = analyze(overrides).find((f) => f.id === "CSW-TLS-005");
  if (!finding) throw new Error("expected CSW-TLS-005");
  return finding;
}

function protocolFinding(overrides: Partial<TlsScanResult>): Finding {
  const finding = analyze(overrides).find((f) => f.id === "CSW-TLS-004");
  if (!finding) throw new Error("expected CSW-TLS-004");
  return finding;
}

describe("hybrid KEX verdict is bound to TLS 1.3", () => {
  it("never reports post-quantum support for a TLS 1.2 session, whatever the probe said", () => {
    // The old probe completed a TLS 1.2 static-RSA handshake and called it
    // "supports X25519MLKEM768 (confirmed)"; the verdict must not trust that.
    const finding = kex({
      protocol: "TLSv1.2",
      cipherName: "AES256-GCM-SHA384",
      groupName: null,
      hybridKex: "supported",
    });
    expect(finding.title).not.toMatch(/supports/);
    expect(finding.pq_status).toBe("vulnerable");
    expect(finding.confidence).toBe("confirmed");
  });

  it("rates RSA key transport (no forward secrecy) high: the worst harvest-now case", () => {
    const finding = kex({ protocol: "TLSv1.2", cipherName: "AES256-GCM-SHA384", groupName: null });
    expect(finding.severity).toBe("high");
    expect(finding.title).toMatch(/without forward secrecy/);
    expect(finding.algorithm).toBe("static-RSA-key-exchange");
  });

  it("labels TLS 1.2 ECDHE and DHE key exchange", () => {
    const ecdhe = kex({ protocol: "TLSv1.2", cipherName: "ECDHE-RSA-AES128-GCM-SHA256", groupName: "prime256v1" });
    expect(ecdhe.algorithm).toBe("ECDHE-P-256");
    expect(ecdhe.severity).toBe("medium");
    expect(ecdhe.title).toContain("TLSv1.2 negotiated ECDHE-P-256");

    const unnamedCurve = kex({ protocol: "TLSv1.2", cipherName: "ECDHE-RSA-AES128-GCM-SHA256", groupName: null });
    expect(unnamedCurve.algorithm).toBe("ECDHE");

    const weakDhe = kex({ protocol: "TLSv1.2", cipherName: "DHE-RSA-AES128-GCM-SHA256", groupName: null, groupBits: 1024 });
    expect(weakDhe.algorithm).toBe("DHE-1024");
    expect(weakDhe.severity).toBe("high");
  });
});

describe("per-group post-quantum probes", () => {
  it("reports an accepted hybrid as transitional and not CNSA 2.0 compliant", () => {
    const finding = kex({ groupName: "X25519MLKEM768", groupProbes: probes(["X25519MLKEM768"]) });
    expect(finding.title).toBe("Server supports hybrid post-quantum key exchange (X25519MLKEM768)");
    expect(finding.pq_status).toBe("transitional");
    expect(finding.confidence).toBe("confirmed");
    expect(finding.recommendation).toMatch(/Not CNSA 2\.0 compliant: CNSA 2\.0 specifies ML-KEM-1024, so ML-KEM-768 groups/);
  });

  it("credits ML-KEM-1024 as the CNSA 2.0 parameter set instead of calling it exposed", () => {
    const hybrid = kex({ groupName: "secp384r1", groupProbes: probes(["SecP384r1MLKEM1024"]) });
    expect(hybrid.pq_status).toBe("transitional");
    expect(hybrid.recommendation).toMatch(/ML-KEM-1024 is available, the key-establishment parameter set CNSA 2\.0 specifies/);

    const pure = kex({ groupName: "MLKEM1024", groupProbes: probes(["MLKEM1024"]) });
    expect(pure.title).toBe("Server supports post-quantum key exchange (MLKEM1024)");
    expect(pure.pq_status).toBe("safe");
  });

  it("lists every accepted group, not just X25519MLKEM768", () => {
    const finding = kex({ groupName: "SecP256r1MLKEM768", groupProbes: probes(["SecP256r1MLKEM768", "SecP384r1MLKEM1024"]) });
    expect(finding.title).toContain("SecP256r1MLKEM768, SecP384r1MLKEM1024");
    expect(finding.algorithm).toBe("SecP256r1MLKEM768");
  });

  it("says exactly which groups were refused, at high (not confirmed) confidence", () => {
    const finding = kex({ groupProbes: probes([]) });
    expect(finding.title).toBe(`No tested post-quantum key-exchange group accepted (tried: ${ALL_GROUPS.join(", ")})`);
    expect(finding.pq_status).toBe("vulnerable");
    expect(finding.confidence).toBe("high");
    expect(finding.algorithm).toBe("ECDHE-X25519");
  });

  it("lowers confidence when some groups could not be tested", () => {
    const partial = ALL_GROUPS.map((group, i): GroupProbeResult => ({ group, outcome: i === 0 ? "rejected" : "inconclusive", detail: "ECONNRESET" }));
    const finding = kex({ groupProbes: partial });
    expect(finding.confidence).toBe("medium");
    expect(finding.recommendation).toMatch(/Not conclusively tested: SecP256r1MLKEM768/);
    expect(finding.evidence).toContain("inconclusive=SecP256r1MLKEM768 (ECONNRESET)");
  });

  it("reports a runtime without ML-KEM as a coverage limit, not a verdict", () => {
    // Node 20 ships OpenSSL 3.0: every group is untestable and the X25519 it
    // negotiated says nothing about the server.
    const untestable = ALL_GROUPS.map((group): GroupProbeResult => ({ group, outcome: "untestable", detail: "local OpenSSL 3.0.19 lacks it" }));
    const finding = kex({ groupProbes: untestable });
    expect(finding.title).toMatch(/not tested: the local TLS runtime lacks ML-KEM/);
    expect(finding.pq_status).toBe("unknown");
    expect(finding.confidence).toBe("low");
    expect(finding.severity).toBe("info");
  });
});

describe("protocol finding", () => {
  it("labels TLS 1.2 quantum-vulnerable (ML-KEM groups are TLS 1.3-only)", () => {
    const finding = protocolFinding({ protocol: "TLSv1.2", cipherName: "ECDHE-RSA-AES128-GCM-SHA256" });
    expect(finding.pq_status).toBe("vulnerable");
    expect(finding.severity).toBe("medium");
    expect(finding.evidence).toContain("cipher=ECDHE-RSA-AES128-GCM-SHA256");
  });

  it("states what a single handshake does not assess", () => {
    expect(protocolFinding({}).recommendation).toMatch(/Not assessed: other protocol versions and cipher suites/);
  });

  it("reports an obsolete protocol reached through the legacy offer", () => {
    const finding = protocolFinding({ protocol: "TLSv1", cipherName: "ECDHE-RSA-AES256-SHA", legacyHandshake: true });
    expect(finding.title).toBe("Obsolete protocol negotiated (TLSv1)");
    expect(finding.severity).toBe("high");
    expect(finding.evidence).toMatch(/legacy/);
  });
});

describe("chain validation", () => {
  it("reports a chain that failed validation instead of ignoring authorizationError", () => {
    const finding = analyze({ authorizationError: "SELF_SIGNED_CERT_IN_CHAIN" }).find((f) => f.id === "CSW-TLS-008");
    expect(finding?.title).toContain("SELF_SIGNED_CERT_IN_CHAIN");
    expect(finding?.pq_status).toBe("unknown");
    expect(analyze({ authorizationError: null }).some((f) => f.id === "CSW-TLS-008")).toBe(false);
  });
});
