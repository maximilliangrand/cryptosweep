/**
 * Primitives broken classically today belong on the act-now board, never on the
 * quantum clock. The scanners record the reason in `Finding.classicalBreak`
 * from the parameters they parsed, so the verdict does not depend on parsing
 * an algorithm label back out of a string.
 */
import { describe, expect, it } from "vitest";
import { defaultProfile } from "../src/model/estate";
import { assessRisk, assessThreat } from "../src/model/risk";
import type { Finding } from "../src/report";
import { scanContent } from "../src/scanners/source";
import { analyzeTls } from "../src/scanners/tls";
import type { CertInfo, TlsScanResult } from "../src/scanners/tls";

const TODAY = "2026-10-01T00:00:00.000Z";
const NOW = new Date(TODAY);
// A distant CRQC year: every quantum verdict is on-track, so only a classical break can be act-now.
const PROFILE = defaultProfile(TODAY, { dataClassId: "secrets", crqcYear: 2050 });

function only(findings: Finding[], ruleId: string): Finding {
  const matches = findings.filter((f) => f.ruleId === ruleId);
  expect(matches, `exactly one ${ruleId} finding`).toHaveLength(1);
  const [first] = matches;
  if (!first) throw new Error(`no ${ruleId} finding`);
  return first;
}

function boardStatus(finding: Finding): string | undefined {
  return assessRisk("t", [finding], PROFILE).assets[0]?.verdict.status;
}

describe("source findings with sub-floor parameters are act-now", () => {
  const cases: Array<{ name: string; path: string; code: string; ruleId: string }> = [
    {
      name: "a 512-bit Diffie-Hellman prime",
      path: "src/dh.js",
      code: 'const crypto = require("crypto");\ncrypto.createDiffieHellman(512);\n',
      ruleId: "source/node-crypto/dh",
    },
    {
      name: "the 1024-bit modp2 group",
      path: "src/dh.js",
      code: 'const crypto = require("crypto");\ncrypto.getDiffieHellman("modp2");\n',
      ruleId: "source/node-crypto/dh",
    },
    {
      name: "createSign over SHA-1",
      path: "src/sign.js",
      code: 'const crypto = require("crypto");\ncrypto.createSign("RSA-SHA1");\n',
      ruleId: "source/node-crypto/signature",
    },
    {
      name: "an EC key on prime192v1",
      path: "src/ec.js",
      code: 'const crypto = require("crypto");\ncrypto.generateKeyPairSync("ec", { namedCurve: "prime192v1" });\n',
      ruleId: "source/node-crypto/keygen-ec",
    },
    {
      name: "a WebCrypto RSASSA key bound to SHA-1",
      path: "src/web.js",
      code:
        'crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" }, true, ["sign"]);\n',
      ruleId: "source/webcrypto/keygen-rsa",
    },
    {
      name: "a JCA 1024-bit DH key pair",
      path: "src/Weak.java",
      code: 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");\nkpg.initialize(1024);\n',
      ruleId: "source/java/keygen-dh",
    },
    {
      name: "a JCA SHA1withRSA signature",
      path: "src/Weak.java",
      code: 'Signature s = Signature.getInstance("SHA1withRSA");\n',
      ruleId: "source/java/rsa-signature",
    },
    {
      name: "a Go PKCS#1 v1.5 signature over crypto.SHA1",
      path: "sign.go",
      code: 'import (\n  "crypto"\n  "crypto/rsa"\n)\nfunc f() { rsa.SignPKCS1v15(nil, key, crypto.SHA1, d) }\n',
      ruleId: "source/go/rsa-signature",
    },
  ];

  for (const { name, path, code, ruleId } of cases) {
    it(name, () => {
      const finding = only(scanContent(path, code), ruleId);
      expect(finding.classicalBreak).toMatch(/SP 800-131A/);
      expect(assessThreat(finding).threats).toEqual(["classical"]);
      expect(boardStatus(finding)).toBe("act-now");
    });
  }

  it("leaves a sound modulus, curve and digest on the quantum clock", () => {
    const sound = scanContent(
      "src/ok.js",
      'const crypto = require("crypto");\ncrypto.generateKeyPairSync("rsa", { modulusLength: 3072 });\ncrypto.createSign("RSA-SHA256");\ncrypto.getDiffieHellman("modp14");\n',
    );
    expect(sound.length).toBeGreaterThan(0);
    for (const finding of sound) {
      expect(finding.classicalBreak).toBeUndefined();
      expect(boardStatus(finding)).toBe("on-track");
    }
  });
});

const LEAF: CertInfo = {
  subject: "weak.example",
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

function tls(overrides: Partial<TlsScanResult>): Finding[] {
  return analyzeTls(
    { protocol: "TLSv1.3", cipherName: "TLS_AES_256_GCM_SHA384", groupName: "X25519", chain: [LEAF], ...overrides },
    "weak.example:443",
    NOW,
  );
}

describe("TLS findings with sub-floor parameters are act-now", () => {
  it("a P-192 (prime192v1) leaf key", () => {
    const leaf = only(tls({ chain: [{ ...LEAF, keyType: "ec", keyBits: null, curve: "prime192v1" }] }), "tls/leaf-public-key");
    expect(leaf.algorithm).toBe("ECDSA-prime192v1");
    expect(leaf.classicalBreak).toMatch(/ECDSA-prime192v1/);
    expect(boardStatus(leaf)).toBe("act-now");
  });

  it("an RSA-1024 leaf key", () => {
    const leaf = only(tls({ chain: [{ ...LEAF, keyBits: 1024 }] }), "tls/leaf-public-key");
    expect(boardStatus(leaf)).toBe("act-now");
  });

  it("a DHE-1024 key exchange", () => {
    const findings = tls({ protocol: "TLSv1.2", cipherName: "DHE-RSA-AES128-GCM-SHA256", groupName: null, groupBits: 1024 });
    const kex = only(findings, "tls/hybrid-kex");
    expect(kex.algorithm).toBe("DHE-1024");
    expect(kex.classicalBreak).toMatch(/DHE-1024/);
    expect(boardStatus(kex)).toBe("act-now");
  });

  it("keeps DHE-2048 and a P-256 leaf on the quantum clock", () => {
    const findings = tls({
      protocol: "TLSv1.2",
      cipherName: "DHE-RSA-AES128-GCM-SHA256",
      groupName: null,
      groupBits: 2048,
      chain: [{ ...LEAF, keyType: "ec", keyBits: null, curve: "P-256" }],
    });
    for (const ruleId of ["tls/hybrid-kex", "tls/leaf-public-key"]) {
      const finding = only(findings, ruleId);
      expect(finding.classicalBreak).toBeUndefined();
      expect(boardStatus(finding)).not.toBe("act-now");
    }
  });
});

describe("the label fallback for findings built without classicalBreak", () => {
  const base: Finding = {
    id: "F",
    severity: "high",
    category: "source",
    title: "t",
    evidence: "e",
    pq_status: "vulnerable",
    recommendation: "r",
  };

  it.each(["DH-1024", "DHE-1024", "FFDHE-1536", "ECDSA-prime192v1", "ECDH-secp192k1", "ECDHE-P-192", "RSA-1024"])(
    "treats %s as broken today",
    (algorithm) => {
      expect(assessThreat({ ...base, algorithm }).threats).toEqual(["classical"]);
    },
  );

  it.each(["DH-2048", "FFDHE-2048", "ECDSA-P-256", "ECDSA-prime256v1", "ECDHE-P-384", "RSA-2048"])(
    "keeps %s on the quantum clock",
    (algorithm) => {
      expect(assessThreat({ ...base, algorithm }).threats).not.toContain("classical");
    },
  );
});

describe("the ledger headline", () => {
  it("names act-now assets when nothing is exposed or overdue", () => {
    const findings = scanContent("src/dh.js", 'const crypto = require("crypto");\ncrypto.createDiffieHellman(512);\n');
    const { ledger } = assessRisk("t", findings, PROFILE);
    expect(ledger.actNowAssets).toBe(1);
    expect(ledger.headline).toMatch(/1 asset\(s\) are broken today without a quantum computer/);
  });
});
