/**
 * CNSA 2.0 in the government-cui ledger. CNSA 2.0 sets parameter sets
 * (ML-KEM-1024, ML-DSA-87) and its own deadlines, so the obligation count is
 * every public-key asset outside them, not only the ones the Mosca clock calls
 * overdue: an X25519MLKEM768 server with an ECDSA P-256 leaf used to report
 * "NSA CNSA 2.0 ... assets: 0".
 */
import { describe, expect, it } from "vitest";
import { signatureAlgorithmName } from "../src/asn1";
import { cnsa2Standing } from "../src/crypto";
import { defaultProfile } from "../src/model/estate";
import { assessRisk } from "../src/model/risk";
import type { RiskModel } from "../src/model/risk";
import type { Finding } from "../src/report";
import { matchDeps } from "../src/scanners/deps";
import { analyzeTls } from "../src/scanners/tls";
import type { CertInfo, GroupProbeResult, TlsScanResult } from "../src/scanners/tls";

const TODAY = "2026-10-01T00:00:00.000Z";
const NOW = new Date(TODAY);
const CUI = defaultProfile(TODAY, { dataClassId: "government-cui" });
const CNSA = "NSA CNSA 2.0 (binding on National Security Systems)";

const ECDSA_LEAF: CertInfo = {
  subject: "cui.example",
  issuer: "Example CA",
  isLeaf: true,
  selfSigned: false,
  keyType: "ec",
  keyBits: null,
  curve: "P-256",
  signatureAlgorithm: "ecdsaWithSHA256",
  signatureOid: "1.2.840.10045.4.3.2",
  validFrom: "2025-01-01T00:00:00.000Z",
  validTo: "2099-01-01T00:00:00.000Z",
};

const ML_DSA_87_LEAF: CertInfo = {
  ...ECDSA_LEAF,
  keyType: "ml-dsa-87",
  curve: null,
  signatureAlgorithm: "ML-DSA-87",
  signatureOid: "2.16.840.1.101.3.4.3.19",
};

const GROUPS = ["X25519MLKEM768", "SecP256r1MLKEM768", "MLKEM768", "SecP384r1MLKEM1024", "MLKEM1024"];

function probes(accepted: readonly string[]): GroupProbeResult[] {
  return GROUPS.map((group) => ({ group, outcome: accepted.includes(group) ? "accepted" : "rejected" }));
}

function tls(overrides: Partial<TlsScanResult>): Finding[] {
  return analyzeTls(
    { protocol: "TLSv1.3", cipherName: "TLS_AES_256_GCM_SHA384", groupName: "X25519MLKEM768", chain: [ECDSA_LEAF], ...overrides },
    "cui.example:443",
    NOW,
    { host: "cui.example", port: 443 },
  );
}

function cnsaCount(risk: RiskModel): number | undefined {
  return risk.ledger.byObligation.find((o) => o.obligation === CNSA)?.assets;
}

describe("the CNSA 2.0 obligation count", () => {
  it("counts an X25519MLKEM768 server with an ECDSA P-256 leaf as non-compliant", () => {
    const risk = assessRisk("cui.example", tls({ groupProbes: probes(["X25519MLKEM768"]) }), CUI);
    const byRule = (ruleId: string) => risk.assets.find((a) => a.ruleId === ruleId);
    expect(byRule("tls/hybrid-kex")?.cnsa2).toBe(false);
    expect(byRule("tls/leaf-public-key")?.cnsa2).toBe(false);
    expect(byRule("tls/leaf-signature")?.cnsa2).toBe(false);
    expect(cnsaCount(risk)).toBe(3);
    // The harvest-now ledger is unchanged: CNSA 2.0 is the only obligation judged by parameter set.
    expect(risk.ledger.byObligation.find((o) => o.obligation === "Harvest-now-decrypt-later exposure")?.assets).toBe(0);
  });

  it("gives a clean count to a server keyed with ML-KEM-1024 and authenticated with ML-DSA-87", () => {
    const findings = tls({ groupName: "SecP384r1MLKEM1024", chain: [ML_DSA_87_LEAF], groupProbes: probes(["SecP384r1MLKEM1024", "MLKEM1024"]) });
    expect(cnsaCount(assessRisk("cui.example", findings, CUI))).toBe(0);
  });

  it("credits an accepted ML-KEM-1024 group even when another group is named first", () => {
    const findings = tls({ chain: [ML_DSA_87_LEAF], groupProbes: probes(["X25519MLKEM768", "MLKEM1024"]) });
    const kex = findings.find((f) => f.ruleId === "tls/hybrid-kex");
    expect(kex?.algorithm).toBe("X25519MLKEM768");
    expect(kex?.cnsa2).toBe(true);
    expect(cnsaCount(assessRisk("cui.example", findings, CUI))).toBe(0);
  });

  it("judges findings without a scanner verdict by algorithm, and dependencies by posture", () => {
    const base = { severity: "info", category: "keys", title: "t", evidence: "e", pq_status: "safe", recommendation: "r" } as const;
    const findings: Finding[] = [
      { ...base, id: "K1", ruleId: "keys/public-key-block", algorithm: "ML-DSA-65", location: { path: "a.pem" } },
      { ...base, id: "K2", ruleId: "keys/public-key-block", algorithm: "ML-DSA-87", location: { path: "b.pem" } },
      ...matchDeps([{ name: "rustls", version: "0.21.0", ecosystem: "cargo", manifestPath: "Cargo.toml" }]),
    ];
    const risk = assessRisk("repo", findings, CUI);
    expect(risk.assets.map((a) => [a.label, a.cnsa2])).toEqual([
      ["ML-DSA-65", false],
      ["ML-DSA-87", true],
      ["rustls (cargo)", false],
    ]);
    expect(cnsaCount(risk)).toBe(2);
  });

  it("leaves documentation, tests and examples out", () => {
    const fixture: Finding = {
      id: "S1",
      ruleId: "source/node-crypto/ecdh",
      severity: "low",
      category: "source",
      title: "t",
      evidence: "tests/ecdh.test.js:3",
      location: { path: "tests/ecdh.test.js", context: "test", line: 3 },
      pq_status: "vulnerable",
      algorithm: "ECDH-P-256",
      recommendation: "r",
    };
    expect(cnsaCount(assessRisk("repo", [fixture], CUI))).toBe(0);
  });

  it("classifies algorithm labels against CNSA 2.0", () => {
    for (const label of ["ML-KEM-1024", "MLKEM1024", "SecP384r1MLKEM1024", "ML-DSA-87", "HashML-DSA-87-with-SHA512", "HSS-LMS", "XMSS"]) {
      expect(cnsa2Standing(label), label).toBe(true);
    }
    for (const label of ["X25519MLKEM768", "ML-KEM-768", "ML-DSA-65", "SLH-DSA-SHA2-128s", "ECDSA-P-384", "RSA-3072", "rsassaPss-sha256", "JWT-ES256"]) {
      expect(cnsa2Standing(label), label).toBe(false);
    }
    for (const label of ["SHA-256", "AES-256-GCM", "JWT-HS256", "MD5"]) expect(cnsa2Standing(label), label).toBeNull();
  });
});

describe("stateful hash-based and pre-hash signatures", () => {
  it("names the HSS/LMS, XMSS and HashML-DSA OIDs", () => {
    expect(signatureAlgorithmName("1.2.840.113549.1.9.16.3.17")).toBe("HSS-LMS");
    expect(signatureAlgorithmName("1.3.6.1.5.5.7.6.34")).toBe("XMSS");
    expect(signatureAlgorithmName("1.3.6.1.5.5.7.6.35")).toBe("XMSSMT");
    expect(signatureAlgorithmName("2.16.840.1.101.3.4.3.34")).toBe("HashML-DSA-87-with-SHA512");
    expect(signatureAlgorithmName("2.16.840.1.101.3.4.3.35")).toBe("HashSLH-DSA-SHA2-128s-with-SHA256");
  });

  it("rates them post-quantum, and holds a TLS PKI to ML-DSA-87 for CNSA 2.0", () => {
    const leafSignature = (signatureAlgorithm: string): Finding | undefined =>
      tls({ chain: [{ ...ECDSA_LEAF, signatureAlgorithm }] }).find((f) => f.ruleId === "tls/leaf-signature");
    const lms = leafSignature("HSS-LMS");
    expect(lms?.pq_status).toBe("safe");
    expect(lms?.severity).toBe("info");
    expect(lms?.cnsa2).toBe(false);
    expect(lms?.recommendation).toMatch(/software and firmware signing/);
    expect(leafSignature("HashML-DSA-87-with-SHA512")?.cnsa2).toBe(true);
    expect(leafSignature("HashML-DSA-65-with-SHA512")?.pq_status).toBe("safe");
  });

  it("types an LMS leaf key from its SPKI OID", () => {
    const leaf = tls({ chain: [{ ...ECDSA_LEAF, keyType: "hss-lms", curve: null }] }).find((f) => f.ruleId === "tls/leaf-public-key");
    expect(leaf?.algorithm).toBe("HSS-LMS");
    expect(leaf?.pq_status).toBe("safe");
    expect(leaf?.references?.map((r) => r.label)).toContain("NIST SP 800-208 (stateful hash-based signatures: LMS, HSS, XMSS, XMSS^MT)");
  });
});
