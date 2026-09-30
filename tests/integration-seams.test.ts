/**
 * The seams between scanners and consumers: the structured fields each scanner
 * sets (`usage`, `certificates`, `protocol`, `oid`, `dependency`, `ruleId`) and
 * what the risk engine, the CBOM and SARIF make of them. Every case runs real
 * scanner output, never hand-built findings, so a scanner that stops setting a
 * field fails here.
 */
import { readFileSync } from "node:fs";
import { X509Certificate } from "node:crypto";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { buildReport } from "../src/report";
import type { Finding } from "../src/report";
import { defaultProfile } from "../src/model/estate";
import { assessRisk, assessThreat } from "../src/model/risk";
import type { CryptoAsset } from "../src/model/risk";
import { toCbom } from "../src/output/cbom";
import { toSarif } from "../src/output/sarif";
import { describeCoverage } from "../src/orchestrate";
import { scanContent } from "../src/scanners/source";
import { analyzeTls, parseCertificate } from "../src/scanners/tls";
import type { CertInfo, TlsScanResult } from "../src/scanners/tls";

const TODAY = "2026-10-01T00:00:00.000Z";
const AT = new Date(TODAY);

function only(findings: Finding[], ruleId: string): Finding {
  const matches = findings.filter((f) => f.ruleId === ruleId);
  const [first] = matches;
  if (!first || matches.length !== 1) throw new Error(`expected one ${ruleId} finding, got ${matches.length}`);
  return first;
}

function certificate(path: string, isLeaf: boolean): CertInfo {
  const der = new X509Certificate(readFileSync(fileURLToPath(new URL(path, import.meta.url)))).raw;
  const parsed = parseCertificate(der, isLeaf);
  if (!parsed) throw new Error(`${path} did not parse`);
  return parsed;
}

function assetOf(assets: CryptoAsset[], ruleId: string): CryptoAsset {
  const asset = assets.find((a) => a.ruleId === ruleId);
  if (!asset) throw new Error(`no asset for ${ruleId}`);
  return asset;
}

describe("source rule usage reaches the risk engine", () => {
  it.each([
    ['const c = require("crypto");\nc.createECDH("secp384r1");', "source/node-crypto/ecdh", ["key-establishment"], "harvest-now"],
    [
      'import { CompactEncrypt } from "jose";\nnew CompactEncrypt(b).setProtectedHeader({ alg: "RSA-OAEP", enc: "A256GCM" });',
      "jwt/jose/rsa-key-transport",
      ["encryption"],
      "harvest-now",
    ],
    [
      'import { CompactEncrypt } from "jose";\nnew CompactEncrypt(b).setProtectedHeader({ alg: "ECDH-ES", enc: "A256GCM" });',
      "jwt/jose/ecdh-key-agreement",
      ["key-establishment"],
      "harvest-now",
    ],
    ['const c = require("crypto");\nc.generateKeyPairSync("ed25519");', "source/node-crypto/keygen-eddsa", ["signature"], "forge-later"],
    ['const c = require("crypto");\nc.generateKeyPairSync("x25519");', "source/node-crypto/keygen-xdh", ["key-establishment"], "harvest-now"],
  ])("%s -> %s is %s", (code, ruleId, usage, threat) => {
    const finding = only(scanContent("src/a.js", code), ruleId);
    expect(finding.usage).toEqual(usage);
    expect(assessThreat(finding).threats[0]).toBe(threat);
  });

  it("leaves an RSA key-generation call undetermined, so both threat models are assessed", () => {
    const finding = only(
      scanContent("src/a.js", 'const c = require("crypto");\nc.generateKeyPairSync("rsa", { modulusLength: 3072 });'),
      "source/node-crypto/keygen-rsa",
    );
    expect(finding.usage).toBeUndefined();
    const assessment = assessThreat(finding);
    expect(assessment.usageAssumed).toBe(true);
    expect(assessment.threats).toEqual(["harvest-now", "forge-later"]);
  });

  it("keeps a non-security SHA-1 (an ETag) and HMAC-SHA1 off the act-now board", () => {
    const findings = scanContent(
      "src/a.js",
      [
        'const { createHash, createHmac } = require("crypto");',
        'res.setHeader("ETag", createHash("sha1").update(body).digest("hex"));',
        'const mac = createHmac("sha1", key).update(body).digest("hex");',
      ].join("\n"),
    );
    const risk = assessRisk("repo", buildReport("repo", findings, AT).findings, defaultProfile(TODAY));
    for (const ruleId of ["source/node-crypto/weak-hash-non-security", "source/node-crypto/legacy-digest"]) {
      expect(assetOf(risk.assets, ruleId).verdict.status).toBe("not-applicable");
    }
    expect(risk.ledger.actNowAssets).toBe(0);
  });

  it("still puts a security-role MD5 on the act-now board", () => {
    const findings = scanContent("src/a.js", 'const c = require("crypto");\nconst passwordHash = c.createHash("md5").update(password).digest("hex");');
    const risk = assessRisk("repo", buildReport("repo", findings, AT).findings, defaultProfile(TODAY));
    expect(assetOf(risk.assets, "source/node-crypto/weak-hash").verdict.status).toBe("act-now");
  });
});

const RSA_LEAF = "./fixtures/certs/rsa2048.pem";
const SHA1_INTERMEDIATE = "./fixtures/tls-certs/sha1-intermediate.pem";

function tls(overrides: Partial<TlsScanResult>): Finding[] {
  const result: TlsScanResult = {
    protocol: "TLSv1.3",
    cipherName: "TLS_AES_256_GCM_SHA384",
    groupName: "X25519",
    groupProbes: [],
    chain: [certificate(RSA_LEAF, true)],
    ...overrides,
  };
  return analyzeTls(result, "example.com:443", AT, { host: "example.com", port: 443 });
}

describe("TLS structured fields reach the risk engine and the CBOM", () => {
  it("treats the leaf key as a harvest-now key-transport key under static RSA, and as authentication otherwise", () => {
    const staticRsa = only(tls({ protocol: "TLSv1.2", cipherName: "AES256-GCM-SHA384", groupName: null }), "tls/leaf-public-key");
    expect(staticRsa.usage).toEqual(["encryption", "authentication"]);
    expect(assessThreat(staticRsa).threats).toEqual(["harvest-now", "forge-later"]);

    const ecdhe = only(tls({}), "tls/leaf-public-key");
    expect(ecdhe.usage).toEqual(["authentication"]);
    expect(assessThreat(ecdhe).threats).toEqual(["forge-later"]);
  });

  it("records the negotiated protocol in structured form, so an obsolete version is a present-day break", () => {
    const modern = only(tls({}), "tls/negotiated-protocol");
    expect(modern.protocol).toEqual({ type: "tls", version: "1.3", cipherSuite: "TLS_AES_256_GCM_SHA384", group: "X25519" });

    const obsolete = only(tls({ protocol: "TLSv1", cipherName: "ECDHE-RSA-AES128-SHA", groupName: "prime256v1" }), "tls/negotiated-protocol");
    expect(obsolete.protocol?.version).toBe("1.0");
    expect(assessThreat(obsolete).threats).toEqual(["classical"]);
  });

  it("inventories the leaf and each served intermediate as certificates with subject, issuer, validity and links", () => {
    const leaf = certificate(RSA_LEAF, true);
    const intermediate = certificate(SHA1_INTERMEDIATE, false);
    const report = buildReport("example.com", tls({ chain: [leaf, intermediate] }), AT);
    const doc = JSON.parse(toCbom(report)) as {
      components: Array<{
        "bom-ref": string;
        name: string;
        cryptoProperties?: { assetType: string; oid?: string; certificateProperties?: Record<string, string> };
      }>;
    };
    const certificates = doc.components.filter((c) => c.cryptoProperties?.assetType === "certificate");
    expect(certificates.map((c) => c.name).sort()).toEqual([leaf.subject, intermediate.subject].sort());
    const leafAsset = certificates.find((c) => c.name === leaf.subject);
    expect(leafAsset?.cryptoProperties?.certificateProperties).toMatchObject({
      subjectName: leaf.subject,
      issuerName: leaf.issuer,
      notValidBefore: leaf.validFrom,
      notValidAfter: leaf.validTo,
    });
    const byRef = new Map(doc.components.map((c) => [c["bom-ref"], c]));
    const signature = byRef.get(leafAsset?.cryptoProperties?.certificateProperties?.signatureAlgorithmRef ?? "");
    expect(signature?.cryptoProperties?.oid).toBe(leaf.signatureOid);
  });

  it("describes the intermediate-signature rule in SARIF from its id", () => {
    const report = buildReport("example.com", tls({ chain: [certificate(RSA_LEAF, true), certificate(SHA1_INTERMEDIATE, false)] }), AT);
    const log = JSON.parse(toSarif(report)) as { runs: Array<{ tool: { driver: { rules: Array<{ id: string; shortDescription: { text: string } }> } } }> };
    const rule = log.runs[0]?.tool.driver.rules.find((r) => r.id === "tls/intermediate-signature");
    expect(rule?.shortDescription.text).toBe("Intermediate certificate signed with a broken or unrecognized algorithm");
  });
});

describe("scan coverage recorded on the report", () => {
  it("marks the TLS check partial when post-quantum key exchange could not be tested", () => {
    const target = { kind: "host" as const, host: "example.com", port: 443 };
    const untested = tls({ groupProbes: [{ group: "X25519MLKEM768", outcome: "untestable", detail: "local OpenSSL lacks it" }] });
    const [partial] = describeCoverage(target, untested);
    expect(partial).toMatchObject({ check: "tls", complete: false });
    expect(partial?.note).toMatch(/local TLS runtime lacks ML-KEM groups/);

    const tested = tls({ groupProbes: [{ group: "X25519MLKEM768", outcome: "accepted" }] });
    expect(describeCoverage(target, tested)).toEqual([
      expect.objectContaining({ check: "tls", complete: true, scope: expect.stringMatching(/^example\.com:443: one handshake/) }),
    ]);
  });

  it("marks the source check partial from the scanner's coverage findings", () => {
    const gap: Finding = {
      id: "CSW-COV-001",
      ruleId: "source/binary-skipped",
      severity: "info",
      category: "source",
      title: "2 binary-looking file(s) were not analysed",
      evidence: "a.der, b.jks",
      pq_status: "unknown",
      recommendation: "r",
    };
    const coverage = describeCoverage({ kind: "path", dir: "/repo" }, [gap]);
    expect(coverage.map((c) => [c.check, c.complete, c.note])).toEqual([
      ["source", false, gap.title],
      ["deps", true, undefined],
    ]);
  });
});
