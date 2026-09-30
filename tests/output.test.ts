import { describe, expect, it } from "vitest";
import { buildReport, failsThreshold, sanitizeText, toMarkdown } from "../src/report";
import type { Finding } from "../src/report";
import { toCbom, describeAlgorithm } from "../src/output/cbom";
import { toSarif } from "../src/output/sarif";
import { matchDeps } from "../src/scanners/deps";
import { scanContent } from "../src/scanners/source";

const AT = new Date("2026-01-01T00:00:00.000Z");

const FINDINGS: Finding[] = [
  {
    id: "CSW-TLS-001",
    ruleId: "tls/leaf-public-key",
    severity: "high",
    category: "tls",
    title: "Leaf public key: RSA-2048",
    evidence: "example.com:443 (example.com)",
    location: { host: "example.com", port: 443 },
    pq_status: "vulnerable",
    confidence: "confirmed",
    algorithm: "RSA-2048",
    recommendation: "Plan migration to ML-DSA.",
    references: [{ label: "NIST FIPS 204 (ML-DSA)", url: "https://csrc.nist.gov/pubs/fips/204/final" }],
  },
  {
    id: "CSW-KEY-001",
    ruleId: "keys/private-key",
    severity: "critical",
    category: "keys",
    title: "Hardcoded private key block",
    evidence: "src/secrets.ts:12",
    location: { path: "src/secrets.ts", line: 12 },
    pq_status: "vulnerable",
    confidence: "high",
    recommendation: "Rotate and remove from source.",
  },
];

const CHAIN_FINDING: Finding = {
  id: "CSW-TLS-003",
  ruleId: "tls/chain-classical",
  severity: "medium",
  category: "tls",
  title: "Certificate chain has 1 intermediate(s) using classical crypto",
  evidence: "WE1 (ECDSA P-256)",
  location: { host: "example.com", port: 443 },
  pq_status: "vulnerable",
  confidence: "confirmed",
  recommendation: "The whole chain must migrate.",
};

const PROTOCOL_FINDING: Finding = {
  id: "CSW-TLS-004",
  ruleId: "tls/negotiated-protocol",
  severity: "info",
  category: "tls",
  title: "Negotiated TLSv1.3",
  evidence: "example.com:443",
  location: { host: "example.com", port: 443 },
  pq_status: "transitional",
  confidence: "confirmed",
  recommendation: "Keep TLS 1.3 enabled.",
};

describe("describeAlgorithm", () => {
  it("classifies classical algorithms as quantum-broken (level 0)", () => {
    expect(describeAlgorithm("RSA-2048")).toMatchObject({ primitive: "signature", nistQuantumSecurityLevel: 0 });
    expect(describeAlgorithm("ECDSA-P-256").nistQuantumSecurityLevel).toBe(0);
    expect(describeAlgorithm("Ed25519").oid).toBe("1.3.101.112");
  });

  it("classifies PQ algorithms with a non-zero NIST level", () => {
    expect(describeAlgorithm("ML-DSA-87")).toMatchObject({ primitive: "signature", nistQuantumSecurityLevel: 5 });
    expect(describeAlgorithm("X25519MLKEM768")).toMatchObject({ primitive: "kem", nistQuantumSecurityLevel: 3 });
  });
});

describe("toCbom", () => {
  it("emits a valid CycloneDX 1.6 CBOM with a cryptographic-asset component", () => {
    const report = buildReport("example.com", FINDINGS, AT);
    const doc = JSON.parse(toCbom(report));
    expect(doc.bomFormat).toBe("CycloneDX");
    expect(doc.specVersion).toBe("1.6");
    expect(doc.serialNumber).toMatch(/^urn:uuid:[0-9a-f-]+$/);
    expect(doc.metadata.component.name).toBe("example.com");

    const rsa = doc.components.find((c: { name: string }) => c.name === "RSA-2048");
    expect(rsa.type).toBe("cryptographic-asset");
    expect(rsa.cryptoProperties.assetType).toBe("algorithm");
    expect(rsa.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel).toBe(0);
    expect(rsa.properties).toContainEqual({ name: "cryptosweep:pq_status", value: "vulnerable" });
  });

  it("is deterministic for identical input", () => {
    const report = buildReport("example.com", FINDINGS, AT);
    expect(toCbom(report)).toBe(toCbom(report));
  });

  it("inventories assets that name no algorithm instead of silently dropping them", () => {
    const report = buildReport("example.com", [...FINDINGS, CHAIN_FINDING, PROTOCOL_FINDING], AT);
    const doc = JSON.parse(toCbom(report)) as { components: Array<{ name: string; cryptoProperties: Record<string, unknown> }> };

    // The critical hardcoded private key was absent from the "bill of materials".
    const key = doc.components.find((c) => /private key material/i.test(c.name));
    expect(key?.cryptoProperties.assetType).toBe("related-crypto-material");
    expect(key?.cryptoProperties.relatedCryptoMaterialProperties).toEqual({ type: "private-key" });

    const chain = doc.components.find((c) => c.name === "TLS certificate chain");
    expect(chain?.cryptoProperties.assetType).toBe("certificate");

    const protocol = doc.components.find((c) => c.name === "Negotiated TLS protocol");
    expect(protocol?.cryptoProperties.assetType).toBe("protocol");
    expect(protocol?.cryptoProperties.protocolProperties).toEqual({ type: "tls", version: "1.3" });
  });
});

const RULE_FIXTURE = [
  'import crypto from "node:crypto";',
  'import jwt from "jsonwebtoken";',
  'crypto.createHash("md5"); crypto.createHash("sha1");',
  'crypto.createCipheriv("des-ede3-cbc", k, iv); crypto.createCipheriv("rc4", k, iv);',
  'jwt.sign(p, k, { algorithm: "RS256" }); jwt.verify(t, k, { algorithms: ["HS256"] });',
  "const key = `-----BEGIN RSA PRIVATE KEY-----",
  "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun",
  "-----END RSA PRIVATE KEY-----`;",
  "const pub = `-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqh\n-----END PUBLIC KEY-----`;",
].join("\n");

type SarifLog = {
  runs: Array<{
    tool: { driver: { informationUri: string; rules: Array<{ id: string; shortDescription: { text: string }; helpUri: string; properties: Record<string, unknown> }> } };
    results: Array<{ ruleId: string; level: string; properties: Record<string, string>; locations?: Array<{ physicalLocation: { artifactLocation: { uri: string; uriBaseId?: string } } }> }>;
  }>;
};

describe("toSarif rule identity (real scanner output)", () => {
  const log = (): SarifLog => JSON.parse(toSarif(buildReport("repo", scanContent("src/app.ts", RULE_FIXTURE), AT))) as SarifLog;

  it("gives MD5, SHA-1, DES and RC4, RS256 and HS256, and private and public keys their own rules", () => {
    const run = log().runs[0];
    const ruleOf = (predicate: (r: { properties: Record<string, string> }) => boolean): string | undefined =>
      run?.results.find(predicate)?.ruleId;
    const ids = run?.results.map((r) => r.ruleId) ?? [];
    expect(new Set(ids).size).toBe(ids.length); // one result per rule in this fixture
    expect(run?.tool.driver.rules).toHaveLength(ids.length);
    expect(ruleOf((r) => r.properties.evidence === "src/app.ts:6")).not.toBe(ruleOf((r) => r.properties.evidence === "src/app.ts:9"));
  });

  it("builds rule metadata from the rule id alone, so result order cannot change it", () => {
    const findings = scanContent("src/app.ts", RULE_FIXTURE);
    const forward = JSON.parse(toSarif(buildReport("repo", findings, AT))) as SarifLog;
    const backward = JSON.parse(toSarif(buildReport("repo", [...findings].reverse(), AT))) as SarifLog;
    expect(backward.runs[0]?.tool.driver.rules).toEqual(forward.runs[0]?.tool.driver.rules);
  });

  it("does not score a low result by a critical sibling", () => {
    const run = log().runs[0];
    const hs = run?.results.find((r) => r.properties.severity === "low");
    expect(hs?.level).toBe("note");
    expect(hs?.properties["security-severity"]).toBe("3.0");
    expect(run?.tool.driver.rules.find((rule) => rule.id === hs?.ruleId)?.properties["security-severity"]).toBe("3.0");
  });

  it("points tool and rule help at the current repository", () => {
    const sarif = toSarif(buildReport("repo", scanContent("src/app.ts", RULE_FIXTURE), AT));
    const run = (JSON.parse(sarif) as SarifLog).runs[0];
    expect(run?.tool.driver.informationUri).toBe("https://github.com/maximilliangrand/cryptosweep");
    expect(run?.tool.driver.rules.every((r) => r.helpUri.startsWith("https://github.com/maximilliangrand/cryptosweep"))).toBe(true);
    expect(sarif).not.toMatch(/Grandillionaire/);
  });

  it("describes dependency rules from the registry", () => {
    const findings = matchDeps([{ name: "tweetnacl", version: "1.0.3", ecosystem: "npm", manifestPath: "package.json" }]);
    const rule = (JSON.parse(toSarif(buildReport("repo", findings, AT))) as SarifLog).runs[0]?.tool.driver.rules[0];
    expect(rule?.id).toBe("deps/npm-tweetnacl");
    expect(rule?.shortDescription.text).toMatch(/tweetnacl/);
  });
});

describe("toSarif artifact locations", () => {
  const uriOf = (path: string): { uri: string; uriBaseId?: string } | undefined => {
    const finding: Finding = { ...(FINDINGS[1] as Finding), location: { path, line: 1 } };
    const log = JSON.parse(toSarif(buildReport("repo", [finding], AT))) as SarifLog;
    return log.runs[0]?.results[0]?.locations?.[0]?.physicalLocation.artifactLocation;
  };

  it("emits repository-relative URIs against %SRCROOT%", () => {
    expect(uriOf("src/app.ts")).toEqual({ uri: "src/app.ts", uriBaseId: "%SRCROOT%" });
    expect(uriOf("./src/app.ts")).toEqual({ uri: "src/app.ts", uriBaseId: "%SRCROOT%" });
    expect(uriOf("src\\win\\app.ts")).toEqual({ uri: "src/win/app.ts", uriBaseId: "%SRCROOT%" });
  });

  it("percent-encodes characters that would break or redirect the URI", () => {
    expect(uriOf("docs/My Notes #1?.md")?.uri).toBe("docs/My%20Notes%20%231%3F.md");
    expect(uriOf("src/ünï.ts")?.uri).toBe("src/%C3%BCn%C3%AF.ts");
    expect(uriOf("c:weird/file.ts")?.uri).toBe("c%3Aweird/file.ts");
  });

  it("does not pass an absolute path off as repository-relative", () => {
    expect(uriOf("/tmp/checkout/src/app.ts")).toEqual({ uri: "file:///tmp/checkout/src/app.ts" });
    expect(uriOf("C:\\repo\\app.ts")).toEqual({ uri: "file:///C:/repo/app.ts" });
  });

  it("brackets an IPv6 endpoint", () => {
    const finding: Finding = { ...(FINDINGS[0] as Finding), location: { host: "2001:db8::1", port: 443 } };
    const log = JSON.parse(toSarif(buildReport("repo", [finding], AT))) as SarifLog;
    expect(log.runs[0]?.results[0]?.locations?.[0]?.physicalLocation.artifactLocation.uri).toBe("tls://[2001:db8::1]:443");
  });
});

describe("toSarif", () => {
  it("emits a valid SARIF 2.1.0 log with rules, levels, and file locations", () => {
    const report = buildReport("example.com", FINDINGS, AT);
    const log = JSON.parse(toSarif(report));
    expect(log.version).toBe("2.1.0");
    const run = log.runs[0];
    expect(run.tool.driver.name).toBe("cryptosweep");
    expect(run.tool.driver.rules.length).toBeGreaterThan(0);

    const critical = run.results.find((r: { ruleId: string }) => r.ruleId === "keys/private-key");
    expect(critical.level).toBe("error");
    expect(critical.locations[0].physicalLocation.artifactLocation).toEqual({ uri: "src/secrets.ts", uriBaseId: "%SRCROOT%" });
    expect(critical.locations[0].physicalLocation.region.startLine).toBe(12);

    const rule = run.tool.driver.rules.find((r: { id: string }) => r.id === "keys/private-key");
    expect(rule.properties["security-severity"]).toBe("9.5");
  });

  it("anchors network findings to host:port so code scanning does not drop them", () => {
    const report = buildReport("example.com", [...FINDINGS, CHAIN_FINDING, PROTOCOL_FINDING], AT);
    const log = JSON.parse(toSarif(report)) as {
      runs: Array<{ results: Array<{ ruleId: string; locations?: Array<Record<string, unknown>> }> }>;
    };
    const results = log.runs[0]?.results ?? [];
    // Every result must carry a location; TLS results used to carry none at all.
    expect(results.filter((r) => (r.locations ?? []).length > 0)).toHaveLength(results.length);

    const tls = results.find((r) => r.ruleId === "tls/leaf-public-key");
    const location = tls?.locations?.[0] as {
      physicalLocation: { artifactLocation: { uri: string } };
      logicalLocations: Array<{ name: string; kind: string }>;
    };
    expect(location.physicalLocation.artifactLocation.uri).toBe("tls://example.com:443");
    expect(location.logicalLocations[0]).toEqual({
      name: "example.com:443",
      kind: "resource",
      fullyQualifiedName: "example.com:443",
    });
  });
});

describe("failsThreshold", () => {
  it("fires when a finding meets or exceeds the threshold", () => {
    const report = buildReport("example.com", FINDINGS, AT);
    expect(failsThreshold(report, "critical")).toBe(true);
    expect(failsThreshold(report, "high")).toBe(true);
  });

  it("does not fire when all findings are below the threshold", () => {
    const low: Finding[] = [
      { id: "X", severity: "low", category: "tls", title: "t", evidence: "e", pq_status: "unknown", recommendation: "r" },
    ];
    const report = buildReport("example.com", low, AT);
    expect(failsThreshold(report, "high")).toBe(false);
    expect(failsThreshold(report, "low")).toBe(true);
  });
});

describe("report rule ids", () => {
  it("derives distinct rule ids per kind when a scanner sets none", () => {
    const report = buildReport("repo", scanContent("src/app.ts", RULE_FIXTURE), AT);
    const ids = report.findings.map((f) => f.ruleId);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).not.toContain("source/csw-src");
    expect(ids).toContain("source/md5");
    expect(ids).toContain("jwt/rs256");
  });
});

/** True if the text holds a terminal-control or bidi-override character (newline and tab allowed). */
function hasUnsafeCharacter(text: string): boolean {
  return [...text].some((char) => {
    const code = char.codePointAt(0) ?? 0;
    const control = (code < 0x20 && code !== 0x09 && code !== 0x0a) || (code >= 0x7f && code <= 0x9f);
    return control || (code >= 0x202a && code <= 0x202e);
  });
}

describe("untrusted strings in terminal and Markdown output", () => {
  const hostile: Finding = {
    id: "CSW-KEY-001",
    ruleId: "keys/private-key",
    severity: "critical",
    category: "keys",
    title: "Hardcoded private key block",
    evidence: "repo/\u001b]0;PWNED\u0007\u001b[31mRED\u001b[0m | fake | [x](https://evil.example) <img src=x>.key:1",
    pq_status: "vulnerable",
    recommendation: "Rotate\u202e it.",
  };

  it("escapes control characters and bidi overrides visibly and idempotently", () => {
    expect(sanitizeText("a\u001b[31mb\u0007c\td\u202ee")).toBe("a\\x1b[31mb\\x07c\td\\u202ee");
    expect(sanitizeText(sanitizeText("x\u009by"))).toBe(sanitizeText("x\u009by"));
    expect(sanitizeText("plain text, unchanged")).toBe("plain text, unchanged");
  });

  it("never lets an escape sequence or Markdown/HTML syntax from a file name through", () => {
    const markdown = toMarkdown(buildReport("repo\u001b[2J", [hostile], AT));
    expect(hasUnsafeCharacter(markdown)).toBe(false);
    expect(markdown).toContain("\\\\x1b");
    expect(markdown).not.toContain("[x](https://evil.example)");
    expect(markdown).toContain("\\[x\\](https://evil.example)");
    expect(markdown).not.toMatch(/(?<!\\)<img/);
    expect(markdown).toContain("\\<img");
    // The pipe cannot open a new table cell.
    const row = markdown.split("\n").find((line) => line.includes("Hardcoded private key block")) ?? "";
    expect(row.split(/(?<!\\)\|/).length).toBe(8);
  });

  it("sanitizes finding strings at the report boundary for every consumer", () => {
    const [finding] = buildReport("repo", [hostile], AT).findings;
    expect(hasUnsafeCharacter(finding?.evidence ?? "")).toBe(false);
    expect(finding?.recommendation).toBe("Rotate\\u202e it.");
  });
});

describe("empty results", () => {
  it("scopes the empty message to the checks that ran", () => {
    const markdown = toMarkdown(buildReport("clean.example.com", [], AT));
    expect(markdown).not.toMatch(/No quantum-vulnerable primitives detected/);
    expect(markdown).toContain("No findings from the checks that ran.");
    expect(markdown).toMatch(/does not record which checks ran/);
  });

  it("lists recorded coverage and flags partial coverage", () => {
    const report = buildReport("repo", [], AT, [
      { check: "source", scope: "412 files", complete: false, note: "2 files over 2 MB skipped" },
      { check: "deps", scope: "3 manifests", complete: true },
    ]);
    const markdown = toMarkdown(report);
    expect(markdown).toContain("No findings from the checks that ran.");
    expect(markdown).toMatch(/Coverage was partial/);
    expect(markdown).toContain("- source: 412 files (partial: 2 files over 2 MB skipped)");
    expect(markdown).toContain("- deps: 3 manifests (complete)");
  });
});
