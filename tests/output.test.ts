import { readFileSync } from "node:fs";
import { X509Certificate } from "node:crypto";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { buildReport, failsThreshold, sanitizeText, toMarkdown } from "../src/report";
import type { Finding } from "../src/report";
import { toCbom, describeAlgorithm } from "../src/output/cbom";
import { toSarif } from "../src/output/sarif";
import { signatureAlgorithmName } from "../src/asn1";
import { matchDeps } from "../src/scanners/deps";
import { scanContent } from "../src/scanners/source";
import { analyzeTls, parseCertificate } from "../src/scanners/tls";

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

  it.each([
    ["ML-KEM-512", 1],
    ["ML-KEM-768", 3],
    ["ML-KEM-1024", 5],
    ["MLKEM1024", 5],
    ["ML-DSA-44", 2],
    ["ML-DSA-65", 3],
    ["ML-DSA-87", 5],
    ["SLH-DSA-SHA2-128s", 1],
    ["SLH-DSA-SHAKE-128f", 1],
    ["SLH-DSA-SHA2-192f", 3],
    ["SLH-DSA-SHAKE-192s", 3],
    ["SLH-DSA-SHA2-256s", 5],
    ["SLH-DSA-SHAKE-256f", 5],
    ["SecP384r1MLKEM1024", 5],
  ])("gives %s NIST category %i", (label, level) => {
    expect(describeAlgorithm(label).nistQuantumSecurityLevel).toBe(level);
  });

  it("uses parameter-set identifiers as CycloneDX defines them", () => {
    expect(describeAlgorithm("ML-DSA-65").parameterSetIdentifier).toBe("65");
    expect(describeAlgorithm("ML-KEM-768").parameterSetIdentifier).toBe("768");
    expect(describeAlgorithm("SLH-DSA-SHA2-128s").parameterSetIdentifier).toBe("SHA2-128s");
    expect(describeAlgorithm("RSA-2048").parameterSetIdentifier).toBe("2048");
    // The curve is a curve, not a parameter set.
    expect(describeAlgorithm("ECDSA-P-256")).toMatchObject({ curve: "secp256r1", classicalSecurityLevel: 128 });
    expect(describeAlgorithm("ECDSA-P-256").parameterSetIdentifier).toBeUndefined();
  });

  it.each([
    ["RC4", "stream-cipher"],
    ["DES-EDE3-CBC", "block-cipher"],
    ["AES-128-CBC", "block-cipher"],
    ["AES-256-GCM", "ae"],
    ["MD5", "hash"],
    ["SHA-1", "hash"],
    ["SHA-256", "hash"],
    ["X25519", "key-agree"],
    ["ECDH-P-256", "key-agree"],
    ["ML-KEM-768", "kem"],
    ["ML-DSA-65", "signature"],
    ["ECDSA-P-384", "signature"],
    ["RSA-3072", "signature"],
    ["JWT-HS256", "mac"],
  ])("types %s as %s", (label, primitive) => {
    expect(describeAlgorithm(label).primitive).toBe(primitive);
  });

  it("types RSA used for encryption as pke", () => {
    expect(describeAlgorithm("RSA-2048", ["encryption"]).primitive).toBe("pke");
    expect(describeAlgorithm("RSA-2048", ["encryption", "signature"]).primitive).toBe("signature");
  });

  it("gives signature algorithms their signature OID, not the key OID", () => {
    expect(describeAlgorithm("sha256WithRSAEncryption").oid).toBe("1.2.840.113549.1.1.11");
    expect(describeAlgorithm("rsassaPss").oid).toBe("1.2.840.113549.1.1.10");
    expect(describeAlgorithm("ecdsaWithSHA384").oid).toBe("1.2.840.10045.4.3.3");
    expect(describeAlgorithm("ML-DSA-65").oid).toBe("2.16.840.1.101.3.4.3.18");
    expect(describeAlgorithm("JWT-ES256").oid).toBe("1.2.840.10045.4.3.2");
  });

  it("agrees with the ASN.1 reader on every signature OID it names", () => {
    const names = [
      "md2WithRSAEncryption", "md4WithRSAEncryption", "md5WithRSAEncryption", "sha1WithRSAEncryption",
      "sha224WithRSAEncryption", "sha256WithRSAEncryption", "sha384WithRSAEncryption", "sha512WithRSAEncryption",
      "rsassaPss", "dsaWithSHA1", "dsaWithSHA224", "dsaWithSHA256", "ecdsaWithSHA1", "ecdsaWithSHA224",
      "ecdsaWithSHA256", "ecdsaWithSHA384", "ecdsaWithSHA512", "Ed25519", "Ed448", "ML-DSA-44", "ML-DSA-65",
      "ML-DSA-87", "SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-256f",
    ];
    for (const name of names) {
      const { oid } = describeAlgorithm(name);
      expect(oid, name).toBeDefined();
      expect(signatureAlgorithmName(oid ?? null), name).toBe(name);
    }
  });

  it("omits a NIST level it cannot determine rather than claiming 0", () => {
    expect(describeAlgorithm("JWT-HS256").nistQuantumSecurityLevel).toBeUndefined();
    expect(describeAlgorithm("AES").nistQuantumSecurityLevel).toBeUndefined();
    expect(describeAlgorithm("unknown-key")).toEqual({ primitive: "unknown" });
  });
});

const CERTS = fileURLToPath(new URL("./fixtures/certs/", import.meta.url));

function leafFindings(fixture: string): Finding[] {
  const leaf = parseCertificate(new X509Certificate(readFileSync(`${CERTS}${fixture}`)).raw, true);
  if (!leaf) throw new Error(`${fixture} did not parse`);
  return analyzeTls({ protocol: "TLSv1.3", cipherName: null, groupName: null, hybridKex: "unsupported", chain: [leaf] }, "example.com:443", AT, {
    host: "example.com",
    port: 443,
  });
}

type CbomComponent = {
  type: string;
  "bom-ref": string;
  name: string;
  version?: string;
  purl?: string;
  cryptoProperties?: {
    assetType: string;
    oid?: string;
    algorithmProperties?: { primitive?: string };
    certificateProperties?: Record<string, string>;
    relatedCryptoMaterialProperties?: { type?: string; algorithmRef?: string; size?: number };
  };
};

type CbomDoc = {
  components: CbomComponent[];
  dependencies?: Array<{ ref: string; dependsOn?: string[]; provides?: string[] }>;
};

describe("toCbom from real scanner output", () => {
  it("emits the certificate's signature OID from its ASN.1, not the key OID", () => {
    const doc = JSON.parse(toCbom(buildReport("example.com", leafFindings("rsa2048.pem"), AT))) as CbomDoc;
    const signature = doc.components.find((c) => c.name === "sha256WithRSAEncryption");
    expect(signature?.cryptoProperties?.oid).toBe("1.2.840.113549.1.1.11");
    const key = doc.components.find((c) => c.name === "RSA-2048");
    expect(key?.cryptoProperties?.oid).toBe("1.2.840.113549.1.1.1");
  });

  it("prefers an OID the scanner read over the catalogue, whichever finding comes first", () => {
    const catalogued: Finding = { ...(FINDINGS[0] as Finding), id: "A", ruleId: "tls/leaf-signature", algorithm: "sha256WithRSAEncryption" };
    const read: Finding = { ...catalogued, id: "B", oid: "1.2.3.4" };
    for (const order of [[read, catalogued], [catalogued, read]]) {
      const doc = JSON.parse(toCbom(buildReport("example.com", order, AT))) as CbomDoc;
      expect(doc.components.find((c) => c.name === "sha256WithRSAEncryption")?.cryptoProperties?.oid).toBe("1.2.3.4");
    }
  });

  it("sanitizes display names built from untrusted paths", () => {
    const findings = scanContent("src/evil\u001b]0;x\u0007.key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n-----END RSA PRIVATE KEY-----");
    const doc = JSON.parse(toCbom(buildReport("repo", findings, AT))) as CbomDoc;
    const key = doc.components.find((c) => c.cryptoProperties?.assetType === "related-crypto-material");
    expect(key?.name).toBe("Private key material (src/evil\\x1b]0;x\\x07.key:1)");
  });

  it("links the leaf certificate to its signature algorithm and public key", () => {
    const doc = JSON.parse(toCbom(buildReport("example.com", leafFindings("ec-p256.pem"), AT))) as CbomDoc;
    const certificate = doc.components.find((c) => c.cryptoProperties?.assetType === "certificate");
    const props = certificate?.cryptoProperties?.certificateProperties ?? {};
    const byRef = new Map(doc.components.map((c) => [c["bom-ref"], c]));
    expect(byRef.get(props.signatureAlgorithmRef ?? "")?.name).toBe("ecdsaWithSHA256");
    const publicKey = byRef.get(props.subjectPublicKeyRef ?? "");
    expect(publicKey?.cryptoProperties?.relatedCryptoMaterialProperties?.type).toBe("public-key");
    expect(byRef.get(publicKey?.cryptoProperties?.relatedCryptoMaterialProperties?.algorithmRef ?? "")?.name).toBe("ECDSA-P-256");
  });

  it("includes parsed certificate details (subject, issuer, validity) when the finding carries them", () => {
    const leaf = parseCertificate(new X509Certificate(readFileSync(`${CERTS}rsa2048.pem`)).raw, true);
    if (!leaf) throw new Error("fixture did not parse");
    const finding: Finding = {
      id: "CSW-TLS-002",
      ruleId: "tls/leaf-signature",
      severity: "medium",
      category: "tls",
      title: `Leaf signature algorithm: ${leaf.signatureAlgorithm}`,
      evidence: "example.com:443",
      location: { host: "example.com", port: 443 },
      pq_status: "vulnerable",
      algorithm: leaf.signatureAlgorithm,
      recommendation: "Plan ML-DSA.",
      certificates: [
        {
          subject: leaf.subject,
          issuer: leaf.issuer,
          notValidBefore: leaf.validFrom,
          notValidAfter: leaf.validTo,
          signatureAlgorithm: leaf.signatureAlgorithm,
          signatureOid: leaf.signatureOid ?? undefined,
          publicKey: "RSA-2048",
          publicKeyBits: 2048,
        },
      ],
    };
    const doc = JSON.parse(toCbom(buildReport("example.com", [finding], AT))) as CbomDoc;
    const certificate = doc.components.find((c) => c.cryptoProperties?.assetType === "certificate");
    expect(certificate?.cryptoProperties?.certificateProperties).toMatchObject({
      subjectName: leaf.subject,
      issuerName: leaf.issuer,
      notValidBefore: leaf.validFrom,
      notValidAfter: leaf.validTo,
      certificateFormat: "X.509",
    });
    const key = doc.components.find((c) => c["bom-ref"] === certificate?.cryptoProperties?.certificateProperties?.subjectPublicKeyRef);
    expect(key?.cryptoProperties?.relatedCryptoMaterialProperties?.size).toBe(2048);
  });

  it("does not add a second, detail-less leaf when a finding for the endpoint carries the parsed certificate", () => {
    const [keyFinding, signatureFinding] = leafFindings("rsa2048.pem");
    if (!keyFinding || !signatureFinding) throw new Error("fixture findings missing");
    const withDetails: Finding = {
      ...signatureFinding,
      certificates: [
        {
          subject: "leaf.example",
          issuer: "ca.example",
          notValidBefore: "2026-01-01T00:00:00.000Z",
          notValidAfter: "2027-01-01T00:00:00.000Z",
          signatureAlgorithm: signatureFinding.algorithm ?? "unknown",
          publicKey: keyFinding.algorithm ?? "unknown-key",
        },
      ],
    };
    const doc = JSON.parse(toCbom(buildReport("example.com", [keyFinding, withDetails], AT))) as CbomDoc;
    const certificates = doc.components.filter((c) => c.cryptoProperties?.assetType === "certificate");
    expect(certificates.map((c) => c.name)).toEqual(["leaf.example"]);
  });

  it("inventories flagged dependencies as library components that provide their algorithms", () => {
    const findings = matchDeps([
      { name: "tweetnacl", version: "1.0.3", ecosystem: "npm", manifestPath: "package.json" },
      { name: "pynacl", version: "1.5.0", ecosystem: "python", manifestPath: "requirements.txt" },
    ]);
    const doc = JSON.parse(toCbom(buildReport("repo", findings, AT))) as CbomDoc;
    const libraries = doc.components.filter((c) => c.type === "library");
    // The scanner's structured coordinates carry the pinned version into the purl.
    expect(libraries.map((c) => c.purl)).toEqual(["pkg:npm/tweetnacl@1.0.3", "pkg:pypi/pynacl@1.5.0"]);
    expect(libraries.map((c) => c.version)).toEqual(["1.0.3", "1.5.0"]);
    const byRef = new Map(doc.components.map((c) => [c["bom-ref"], c]));
    const provided = doc.dependencies?.find((d) => d.ref === "pkg:npm/tweetnacl@1.0.3")?.provides ?? [];
    expect(provided.map((ref) => byRef.get(ref)?.name)).toEqual(["X25519", "Ed25519"]);
    expect(byRef.get(provided[0] ?? "")?.cryptoProperties?.algorithmProperties?.primitive).toBe("key-agree");
    expect(doc.dependencies?.find((d) => d.ref === "target")?.dependsOn).toEqual([
      "pkg:npm/tweetnacl@1.0.3",
      "pkg:pypi/pynacl@1.5.0",
    ]);
  });

  it("puts a pinned structured version into the purl and keeps a range as a property", () => {
    const [pinned, ranged] = matchDeps([
      { name: "tweetnacl", version: "1.0.3", ecosystem: "npm", manifestPath: "package.json" },
      { name: "jsonwebtoken", version: "^9.0.2", ecosystem: "npm", manifestPath: "package.json" },
    ]);
    if (!pinned || !ranged) throw new Error("deps not flagged");
    const report = buildReport("repo", [
      { ...pinned, dependency: { ecosystem: "npm", name: "tweetnacl", version: "1.0.3" } },
      { ...ranged, dependency: { ecosystem: "npm", name: "jsonwebtoken", version: "^9.0.2" } },
    ], AT);
    const doc = JSON.parse(toCbom(report)) as CbomDoc & { components: Array<{ properties?: Array<{ name: string; value: string }> }> };
    const nacl = doc.components.find((c) => c.name === "tweetnacl");
    expect(nacl).toMatchObject({ version: "1.0.3", purl: "pkg:npm/tweetnacl@1.0.3" });
    const jwt = doc.components.find((c) => c.name === "jsonwebtoken") as { version?: string; purl?: string; properties?: Array<{ name: string; value: string }> };
    expect(jwt.version).toBeUndefined();
    expect(jwt.purl).toBe("pkg:npm/jsonwebtoken");
    expect(jwt.properties).toContainEqual({ name: "cryptosweep:declared-version", value: "^9.0.2" });
  });

  it("records where each asset was seen", () => {
    const findings = scanContent("src/app.ts", 'import crypto from "node:crypto";\ncrypto.createHash("md5");\ncrypto.createHash("md5");');
    const doc = JSON.parse(toCbom(buildReport("repo", findings, AT))) as { components: Array<{ name: string; evidence?: { occurrences: unknown[] } }> };
    expect(doc.components.find((c) => c.name === "MD5")?.evidence?.occurrences).toEqual([
      { location: "src/app.ts", line: 2 },
      { location: "src/app.ts", line: 3 },
    ]);
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
    expect(key?.cryptoProperties.relatedCryptoMaterialProperties).toEqual({ type: "private-key", state: "compromised" });

    const protocol = doc.components.find((c) => c.cryptoProperties.assetType === "protocol");
    expect(protocol?.cryptoProperties.protocolProperties).toEqual({ type: "tls" });
  });

  it("never invents assets from finding titles", () => {
    const statusFindings: Finding[] = [
      { ...CHAIN_FINDING },
      {
        id: "CSW-TLS-005",
        ruleId: "tls/hybrid-kex",
        severity: "medium",
        category: "tls",
        title: "Server does not support hybrid post-quantum key exchange",
        evidence: "example.com:443",
        location: { host: "example.com", port: 443 },
        pq_status: "vulnerable",
        recommendation: "Enable X25519MLKEM768.",
      },
      {
        id: "CSW-TLS-007",
        ruleId: "tls/leaf-expiring",
        severity: "low",
        category: "tls",
        title: "Leaf certificate expires within 30 days",
        evidence: "example.com:443",
        location: { host: "example.com", port: 443 },
        pq_status: "unknown",
        recommendation: "Renew.",
      },
    ];
    const doc = JSON.parse(toCbom(buildReport("example.com", statusFindings, AT))) as { components: Array<{ name: string }> };
    expect(doc.components).toEqual([]);
  });

  it("uses the negotiated protocol's structured version, suite and group", () => {
    const report = buildReport("example.com", [{ ...PROTOCOL_FINDING, protocol: { type: "tls", version: "1.3", cipherSuite: "TLS_AES_256_GCM_SHA384", group: "X25519MLKEM768" } }], AT);
    const doc = JSON.parse(toCbom(report)) as { components: Array<{ "bom-ref": string; name: string; cryptoProperties: Record<string, unknown> }> };
    const protocol = doc.components.find((c) => c.cryptoProperties.assetType === "protocol");
    const group = doc.components.find((c) => c.name === "X25519MLKEM768");
    expect(protocol?.cryptoProperties.protocolProperties).toEqual({
      type: "tls",
      version: "1.3",
      cipherSuites: [{ name: "TLS_AES_256_GCM_SHA384" }],
      cryptoRefArray: [group?.["bom-ref"]],
    });
  });
});

/** A real SPKI public key (the RSA-2048 fixture certificate's), so the scanner parses and classifies it. */
const PUBLIC_KEY_PEM = String(
  new X509Certificate(readFileSync(fileURLToPath(new URL("./fixtures/certs/rsa2048.pem", import.meta.url)))).publicKey.export({
    type: "spki",
    format: "pem",
  }),
).trim();

const RULE_FIXTURE = [
  'import crypto from "node:crypto";',
  'import jwt from "jsonwebtoken";',
  'crypto.createHash("md5"); crypto.createHash("sha1");',
  'crypto.createCipheriv("des-ede3-cbc", k, iv); crypto.createCipheriv("rc4", k, iv);',
  'jwt.sign(p, k, { algorithm: "RS256" }); jwt.verify(t, k, { algorithms: ["HS256"] });',
  "const key = `-----BEGIN RSA PRIVATE KEY-----",
  "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun",
  "-----END RSA PRIVATE KEY-----`;",
  `const pub = \`${PUBLIC_KEY_PEM}\`;`,
].join("\n");

type SarifLog = {
  runs: Array<{
    tool: { driver: { informationUri: string; rules: Array<{ id: string; shortDescription: { text: string }; helpUri: string; properties: Record<string, unknown> }> } };
    results: Array<{
      ruleId: string;
      level: string;
      message: { text: string };
      properties: Record<string, string>;
      locations?: Array<{ physicalLocation: { artifactLocation: { uri: string; uriBaseId?: string } } }>;
    }>;
  }>;
};

describe("toSarif rule identity (real scanner output)", () => {
  const log = (): SarifLog => JSON.parse(toSarif(buildReport("repo", scanContent("src/app.ts", RULE_FIXTURE), AT))) as SarifLog;

  it("gives each detector its own rule: weak hash, weak cipher, RS256, HS256, private key and public key", () => {
    const run = log().runs[0];
    const ruleOf = (predicate: (r: { properties: Record<string, string> }) => boolean): string | undefined =>
      run?.results.find(predicate)?.ruleId;
    const ids = [...new Set(run?.results.map((r) => r.ruleId) ?? [])].sort();
    expect(ids).toEqual([
      "jwt/jsonwebtoken/hmac",
      "jwt/jsonwebtoken/rsa",
      "keys/private-key-block",
      "keys/public-key-block",
      "source/node-crypto/weak-cipher",
      "source/node-crypto/weak-hash",
    ]);
    expect(run?.tool.driver.rules.map((rule) => rule.id)).toEqual(ids);
    expect(ruleOf((r) => r.properties.evidence === "src/app.ts:6")).not.toBe(ruleOf((r) => r.properties.evidence === "src/app.ts:9"));
  });

  it("describes source rules from the scanner's catalogue, so a shared rule never takes one result's detail", () => {
    const run = log().runs[0];
    const weakHash = run?.tool.driver.rules.find((rule) => rule.id === "source/node-crypto/weak-hash");
    expect(weakHash?.shortDescription.text).toBe("Weak hash algorithm via node:crypto");
    const messages = run?.results.filter((r) => r.ruleId === "source/node-crypto/weak-hash").map((r) => r.message.text) ?? [];
    expect(messages).toHaveLength(2);
    expect(messages.some((text) => text.includes("(md5)"))).toBe(true);
    expect(messages.some((text) => text.includes("(sha1)"))).toBe(true);
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
    const withoutRuleIds = scanContent("src/app.ts", RULE_FIXTURE).map((finding) => {
      const bare = { ...finding };
      delete bare.ruleId;
      return bare;
    });
    const report = buildReport("repo", withoutRuleIds, AT);
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

describe("describeAlgorithm with an unreadable key size", () => {
  it("still types RSA-? and DSA-? keys, without a size", () => {
    expect(describeAlgorithm("RSA-?")).toEqual({ primitive: "signature", nistQuantumSecurityLevel: 0, oid: "1.2.840.113549.1.1.1" });
    expect(describeAlgorithm("DSA-?").primitive).toBe("signature");
    expect(describeAlgorithm("RSA-PSS-?").oid).toBe("1.2.840.113549.1.1.10");
  });
});
