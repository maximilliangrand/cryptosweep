/**
 * One TLS endpoint's key establishment is one harvest-now asset. The key
 * exchange, a TLS 1.2 protocol (which cannot carry ML-KEM) and a leaf key used
 * for static-RSA key transport used to be counted separately: under
 * legal-privileged, TLS 1.3 X25519 gave 1 exposed asset / 30 risk-years, TLS
 * 1.2 ECDHE 2 / 60 and TLS 1.2 static RSA 3 / 90.
 */
import { describe, expect, it } from "vitest";
import { defaultProfile } from "../src/model/estate";
import { assessRisk } from "../src/model/risk";
import type { Finding } from "../src/report";
import { buildReport } from "../src/report";
import { analyzeTls } from "../src/scanners/tls";
import type { CertInfo, TlsScanResult } from "../src/scanners/tls";

const TODAY = "2026-10-01T00:00:00.000Z";
const PROFILE = defaultProfile(TODAY, { dataClassId: "legal-privileged" });

const LEAF: CertInfo = {
  subject: "tls.example",
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

const REJECTED = ["X25519MLKEM768", "SecP256r1MLKEM768", "MLKEM768", "SecP384r1MLKEM1024", "MLKEM1024"].map((group) => ({
  group,
  outcome: "rejected" as const,
}));

function scan(result: Partial<TlsScanResult>, host = "tls.example"): Finding[] {
  const findings = analyzeTls(
    { protocol: "TLSv1.3", cipherName: "TLS_AES_256_GCM_SHA384", groupName: "X25519", chain: [LEAF], groupProbes: REJECTED, ...result },
    `${host}:443`,
    new Date(TODAY),
    { host, port: 443 },
  );
  return buildReport(host, findings, new Date(TODAY)).findings;
}

const TLS13_X25519 = {};
const TLS12_ECDHE = { protocol: "TLSv1.2", cipherName: "ECDHE-RSA-AES256-GCM-SHA384", groupName: "X25519" };
const TLS12_STATIC_RSA = { protocol: "TLSv1.2", cipherName: "AES256-GCM-SHA384", groupName: null };

describe("a TLS endpoint's key establishment is one asset", () => {
  it.each([
    ["TLS 1.3 X25519", TLS13_X25519],
    ["TLS 1.2 ECDHE", TLS12_ECDHE],
    ["TLS 1.2 static RSA", TLS12_STATIC_RSA],
  ])("%s: one exposed asset, one horizon of risk-years", (_name, result) => {
    const { ledger } = assessRisk("tls.example", scan(result), PROFILE);
    expect(ledger.exposedAssets).toBe(1);
    expect(ledger.exposureRiskYears).toBe(30);
  });

  it("gathers the key exchange, the protocol and the key-transport leaf key under the key exchange's name", () => {
    const findings = scan(TLS12_STATIC_RSA);
    for (const ordered of [findings, [...findings].reverse()]) {
      const risk = assessRisk("tls.example", ordered, PROFILE);
      const exposed = risk.assets.filter((a) => a.verdict.status === "exposed");
      expect(exposed).toHaveLength(1);
      const [asset] = exposed;
      expect(asset?.key).toBe("tls/key-establishment@tls.example:443");
      expect(asset?.ruleId).toBe("tls/hybrid-kex");
      expect(asset?.label).toBe("static-RSA-key-exchange");
      expect(asset?.worstSeverity).toBe("high");
      const rules = findings.filter((f) => asset?.findingIds.includes(f.id)).map((f) => f.ruleId).sort();
      expect(rules).toEqual(["tls/hybrid-kex", "tls/leaf-public-key", "tls/negotiated-protocol"]);
    }
  });

  it("keeps the leaf key's identity role separate when it does not transport keys", () => {
    const risk = assessRisk("tls.example", scan(TLS12_ECDHE), PROFILE);
    expect(risk.assets.find((a) => a.ruleId === "tls/leaf-public-key")?.verdict.threat).toBe("forge-later");
  });

  it("counts two endpoints as two exposures", () => {
    const findings = [...scan(TLS12_ECDHE, "a.example"), ...scan(TLS12_ECDHE, "b.example")];
    expect(assessRisk("estate", findings, PROFILE).ledger.exposedAssets).toBe(2);
  });
});
