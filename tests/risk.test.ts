import { readFileSync } from "node:fs";
import { X509Certificate } from "node:crypto";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { buildReport } from "../src/report";
import type { Finding } from "../src/report";
import { DATA_CLASSES, DEFAULT_MIGRATION_YEARS, defaultProfile } from "../src/model/estate";
import { assessRisk, assessThreat, classifyThreat } from "../src/model/risk";
import type { CryptoAsset } from "../src/model/risk";
import { matchDeps } from "../src/scanners/deps";
import type { ParsedDep } from "../src/scanners/deps";
import { scanContent } from "../src/scanners/source";
import { analyzeTls, parseCertificate } from "../src/scanners/tls";

const TODAY = "2026-01-01T00:00:00.000Z";

function finding(over: Partial<Finding>): Finding {
  return {
    id: "F1",
    severity: "high",
    category: "tls",
    title: "t",
    evidence: "e",
    pq_status: "vulnerable",
    recommendation: "r",
    ...over,
  };
}

describe("classifyThreat", () => {
  it("routes each primitive to the correct threat model", () => {
    // Key exchange -> harvest-now (the only thing that is harvest-now-decrypt-later).
    expect(classifyThreat(finding({ category: "tls", ruleId: "tls/hybrid-kex", algorithm: "X25519" }))).toBe("harvest-now");
    // Signature / identity key -> forge-later.
    expect(classifyThreat(finding({ category: "tls", ruleId: "tls/leaf-public-key", algorithm: "RSA-2048" }))).toBe("forge-later");
    expect(classifyThreat(finding({ category: "jwt", algorithm: "JWT-RS256" }))).toBe("forge-later");
    // Classically broken -> classical, never on the quantum clock.
    expect(classifyThreat(finding({ category: "source", algorithm: "MD5" }))).toBe("classical");
    expect(classifyThreat(finding({ category: "source", algorithm: "SHA-1" }))).toBe("classical");
    expect(classifyThreat(finding({ category: "source", algorithm: "DES-EDE3-CBC" }))).toBe("classical");
    // Not vulnerable -> not applicable.
    expect(classifyThreat(finding({ pq_status: "safe", algorithm: "ML-DSA-65" }))).toBe("not-applicable");
  });

  it("treats key-exchange dependencies as harvest-now and signature libs as forge-later", () => {
    expect(classifyThreat(finding({ category: "deps", ruleId: "deps/cargo-rustls" }))).toBe("harvest-now");
    expect(classifyThreat(finding({ category: "deps", ruleId: "deps/npm-jsonwebtoken" }))).toBe("forge-later");
  });
});

describe("Mosca verdict", () => {
  it("flags long-horizon confidentiality data as already exposed", () => {
    const profile = defaultProfile(TODAY, { dataClassId: "legal-privileged", crqcYear: 2035 });
    const risk = assessRisk("acme", [finding({ id: "K", category: "tls", ruleId: "tls/hybrid-kex", algorithm: "X25519" })], profile);
    const asset = risk.assets[0];
    expect(asset?.verdict.threat).toBe("harvest-now");
    expect(asset?.verdict.status).toBe("exposed"); // 30yr horizon > ~9yr to CRQC
    expect(asset?.verdict.mustCompleteInYears).toBeLessThan(0);
  });

  it("keeps short-horizon confidentiality data off the exposed list", () => {
    const profile = defaultProfile(TODAY, { dataClassId: "public", crqcYear: 2035 });
    const risk = assessRisk("acme", [finding({ category: "tls", ruleId: "tls/hybrid-kex", algorithm: "X25519" })], profile);
    expect(risk.assets[0]?.verdict.status).toBe("not-applicable"); // public data, horizon 0
  });

  it("puts SHA-1 on act-now, never on the quantum clock", () => {
    const profile = defaultProfile(TODAY, { dataClassId: "legal-privileged" });
    const risk = assessRisk("acme", [finding({ category: "source", algorithm: "SHA-1", severity: "high" })], profile);
    const v = risk.assets[0]?.verdict;
    expect(v?.threat).toBe("classical");
    expect(v?.status).toBe("act-now");
  });

  it("gives signatures a forge-later deadline of 'before the CRQC', independent of data horizon", () => {
    // Far CRQC: on track. Note the horizon does not drive forge-later.
    const far = defaultProfile(TODAY, { dataClassId: "legal-privileged", crqcYear: 2035 });
    const onTrack = assessRisk("acme", [finding({ category: "jwt", algorithm: "JWT-RS256" })], far).assets[0]?.verdict;
    expect(onTrack?.threat).toBe("forge-later");
    expect(onTrack?.status).toBe("on-track");
    // A near-term CRQC assumption flips signatures to exposed (cannot rotate in time).
    const near = defaultProfile(TODAY, { crqcYear: 2026 });
    const exposed = assessRisk("acme", [finding({ category: "jwt", algorithm: "JWT-RS256" })], near).assets[0]?.verdict;
    expect(exposed?.status).toBe("exposed");
  });
});

describe("harvest-exposure ledger", () => {
  it("counts only harvest-now-exposed assets and reports weighted risk-years", () => {
    const profile = defaultProfile(TODAY, { dataClassId: "legal-privileged", crqcYear: 2035 });
    const risk = assessRisk(
      "acme",
      [
        finding({ id: "kex", category: "tls", ruleId: "tls/hybrid-kex", algorithm: "X25519" }), // harvest-now exposed
        finding({ id: "sig", category: "tls", ruleId: "tls/leaf-public-key", algorithm: "RSA-2048" }), // forge-later
        finding({ id: "hash", category: "source", algorithm: "MD5" }), // classical
      ],
      profile,
    );
    expect(risk.ledger.exposedAssets).toBe(1);
    // 30yr horizon * 1.0 sensitivity = 30 weighted risk-years.
    expect(risk.ledger.exposureRiskYears).toBeCloseTo(30, 0);
    expect(risk.ledger.headline).toMatch(/harvest-now-decrypt-later/);
  });
});

describe("per-obligation attribution", () => {
  it("attributes assets to the obligation each one actually breaches", () => {
    const profile = defaultProfile(TODAY, { dataClassId: "legal-privileged", crqcYear: 2035 });
    const risk = assessRisk(
      "acme",
      [
        finding({ id: "kex", category: "tls", ruleId: "tls/hybrid-kex", algorithm: "X25519" }), // confidentiality
        finding({ id: "md5", category: "source", algorithm: "MD5" }), // classical strength
        finding({ id: "sig", category: "tls", ruleId: "tls/leaf-public-key", algorithm: "RSA-2048" }), // identity, on track
      ],
      profile,
    );
    const rows = risk.ledger.byObligation;
    expect(rows).toHaveLength(2); // ABA 1.6(c) + HNDL

    const hndl = rows.find((r) => /Harvest-now/.test(r.obligation));
    const aba = rows.find((r) => /ABA Model Rule/.test(r.obligation));
    // 1.6(c) is the duty to safeguard client information; technology competence is Rule 1.1, Comment 8.
    expect(aba?.obligation).toBe("ABA Model Rule 1.6(c) reasonable efforts to safeguard client information");
    // HNDL is breached by the exposed key exchange only.
    expect(hndl?.assets).toBe(1);
    // The competence duty additionally covers already-broken crypto (MD5).
    expect(aba?.assets).toBe(2);
    // The old code reported one constant for every obligation.
    expect(hndl?.assets).not.toBe(aba?.assets);
  });

  it("puts a sub-2048-bit RSA key on the act-now board, not the quantum clock", () => {
    const profile = defaultProfile(TODAY, { dataClassId: "legal-privileged", crqcYear: 2035 });
    const risk = assessRisk("acme", [finding({ category: "tls", ruleId: "tls/leaf-public-key", algorithm: "RSA-1024" })], profile);
    expect(risk.assets[0]?.verdict.threat).toBe("classical");
    expect(risk.assets[0]?.verdict.status).toBe("act-now");
  });
});

describe("ontology graph", () => {
  it("links the system to its data class, obligations, and assets", () => {
    const profile = defaultProfile(TODAY, { dataClassId: "legal-privileged" });
    const risk = assessRisk("acme.com", [finding({ algorithm: "RSA-2048" })], profile);
    const types = risk.graph.nodes.map((n) => n.type);
    expect(types).toContain("system");
    expect(types).toContain("data-class");
    expect(types).toContain("obligation"); // ABA 1.6(c) + HNDL
    expect(types).toContain("asset");
    expect(risk.graph.edges.some((e) => e.rel === "classified-as")).toBe(true);
    expect(risk.graph.edges.some((e) => e.rel === "bound-by")).toBe(true);
    expect(risk.graph.edges.some((e) => e.rel === "uses")).toBe(true);
  });
});

const dep = (name: string, ecosystem: ParsedDep["ecosystem"], manifestPath: string, version = "1.0.0"): ParsedDep => ({
  name,
  ecosystem,
  manifestPath,
  version,
});

function assetFor(assets: CryptoAsset[], predicate: (a: CryptoAsset) => boolean): CryptoAsset {
  const asset = assets.find(predicate);
  if (!asset) throw new Error(`no matching asset among ${assets.map((a) => a.key).join(", ")}`);
  return asset;
}

describe("harvest-now classification from structured fields", () => {
  it("puts encryption and key-agreement libraries in the harvest ledger (real matchDeps output)", () => {
    const findings = matchDeps([
      dep("tweetnacl", "npm", "package.json", "1.0.3"),
      dep("elliptic", "npm", "package.json", "6.5.4"),
      dep("node-rsa", "npm", "package.json", "1.1.1"),
      dep("openpgp", "npm", "package.json", "6.3.2"),
      dep("pynacl", "python", "requirements.txt", "1.5.0"),
      dep("rsa", "python", "requirements.txt", "4.9"),
      dep("rsa", "cargo", "Cargo.toml", "0.9.6"),
      dep("x25519-dalek", "cargo", "Cargo.toml", "2.0.1"),
    ]);
    expect(findings).toHaveLength(8);
    const risk = assessRisk("repo", findings, defaultProfile(TODAY, { dataClassId: "legal-privileged" }));
    for (const asset of risk.assets) {
      expect(asset.verdict.threat, asset.key).toBe("harvest-now");
      expect(asset.verdict.status, asset.key).toBe("exposed");
    }
    expect(risk.ledger.exposedAssets).toBe(8);
    expect(risk.ledger.headline).not.toMatch(/No harvest-now/);
  });

  it("keeps signature-only libraries on the forge-later clock", () => {
    const findings = matchDeps([dep("ed25519-dalek", "cargo", "Cargo.toml"), dep("jsonwebtoken", "npm", "package.json")]);
    const risk = assessRisk("repo", findings, defaultProfile(TODAY, { dataClassId: "legal-privileged" }));
    expect(risk.assets.map((a) => a.verdict.threat)).toEqual(["forge-later", "forge-later"]);
  });

  it("does not depend on the finding title", () => {
    const profile = defaultProfile(TODAY, { dataClassId: "legal-privileged" });
    const base = { id: "K", category: "tls" as const, ruleId: "tls/hybrid-kex" };
    const a = assessRisk("h", [finding({ ...base, title: "Server does not support hybrid post-quantum key exchange" })], profile);
    const b = assessRisk("h", [finding({ ...base, title: "Post-quantum group not offered by server" })], profile);
    expect(a.assets[0]?.verdict.threat).toBe("harvest-now");
    expect(b.assets[0]?.verdict).toEqual(a.assets[0]?.verdict);
  });

  it("lets a scanner's structured usage override the rule table", () => {
    // A TLS 1.2 static-RSA leaf key transports the session key: harvest-now, not forge-later.
    const transport = finding({ ruleId: "tls/leaf-public-key", algorithm: "RSA-2048", usage: ["key-establishment"] });
    expect(classifyThreat(transport)).toBe("harvest-now");
    expect(classifyThreat(finding({ ruleId: "tls/leaf-public-key", algorithm: "RSA-2048" }))).toBe("forge-later");
  });

  it("assesses a primitive of undetermined use under both threat models and says so", () => {
    const risk = assessRisk("h", [finding({ category: "source", ruleId: "source/rsa-keygen", algorithm: "RSA-3072" })], defaultProfile(TODAY));
    const verdict = risk.assets[0]?.verdict;
    expect(assessThreat(finding({ category: "source", ruleId: "source/rsa-keygen", algorithm: "RSA-3072" })).threats).toEqual([
      "harvest-now",
      "forge-later",
    ]);
    expect(verdict?.rationale).toMatch(/Usage undetermined/);
  });

  it("still puts a dual-use library on the forge-later clock for public data", () => {
    const [tweetnacl] = matchDeps([dep("tweetnacl", "npm", "package.json")]);
    if (!tweetnacl) throw new Error("tweetnacl not flagged");
    const verdict = assessRisk("h", [tweetnacl], defaultProfile(TODAY, { dataClassId: "public" })).assets[0]?.verdict;
    expect(verdict?.threat).toBe("forge-later");
    expect(verdict?.status).not.toBe("not-applicable");
  });
});

describe("present-day breaks are act-now, never on the quantum clock", () => {
  /** A real SPKI public key (the RSA-2048 fixture certificate's), so the source scanner parses and classifies it. */
  const PUBLIC_KEY_PEM = String(
    new X509Certificate(readFileSync(fileURLToPath(new URL("./fixtures/certs/rsa2048.pem", import.meta.url)))).publicKey.export({
      type: "spki",
      format: "pem",
    }),
  ).trim();
  const SOURCE = [
    'import jwt from "jsonwebtoken";',
    'jwt.verify(t, k, { algorithms: ["none"] });',
    "const key = `-----BEGIN RSA PRIVATE KEY-----",
    "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun",
    "-----END RSA PRIVATE KEY-----`;",
    `const pub = \`${PUBLIC_KEY_PEM}\`;`,
  ].join("\n");

  it("classifies JWT alg none and a committed private key (real scanContent output) as classical", () => {
    const report = buildReport("repo", scanContent("src/auth.ts", SOURCE));
    const risk = assessRisk("repo", report.findings, defaultProfile(TODAY, { dataClassId: "legal-privileged" }));
    const none = assetFor(risk.assets, (a) => a.label === "JWT-none");
    const secret = assetFor(risk.assets, (a) => a.usage.includes("secret-material"));
    for (const asset of [none, secret]) {
      expect(asset.verdict.threat).toBe("classical");
      expect(asset.verdict.status).toBe("act-now");
    }
    expect(secret.verdict.rationale).toMatch(/compromised/);
    expect(risk.ledger.actNowAssets).toBe(2);
  });

  it("labels a committed private key as key material even when its algorithm is known", () => {
    const risk = assessRisk("repo", [finding({ category: "keys", ruleId: "keys/private-key", algorithm: "RSA-2048" })], defaultProfile(TODAY));
    expect(risk.assets[0]?.label).toBe("Committed private key material (RSA-2048)");
    expect(risk.assets[0]?.verdict.status).toBe("act-now");
  });

  it("never labels an embedded public key as a private key", () => {
    const report = buildReport("repo", scanContent("src/auth.ts", SOURCE));
    const risk = assessRisk("repo", report.findings, defaultProfile(TODAY));
    const keyAssets = risk.assets.filter((a) => a.category === "keys");
    expect(keyAssets).toHaveLength(2);
    const publicKey = assetFor(keyAssets, (a) => !a.usage.includes("secret-material"));
    expect(publicKey.label).not.toMatch(/private/i);
    expect(publicKey.verdict.threat).not.toBe("classical");
  });

  it("puts an MD5-signed certificate (parsed from the fixture) on act-now", () => {
    const der = new X509Certificate(readFileSync(fileURLToPath(new URL("./fixtures/certs/rsa-md5.pem", import.meta.url)))).raw;
    const leaf = parseCertificate(der, true);
    if (!leaf) throw new Error("fixture did not parse");
    const findings = analyzeTls({ protocol: "TLSv1.3", cipherName: null, groupName: null, chain: [leaf] }, "h:443", new Date(TODAY));
    const risk = assessRisk("h", findings, defaultProfile(TODAY));
    const signature = assetFor(risk.assets, (a) => a.label === "md5WithRSAEncryption");
    expect(signature.verdict.threat).toBe("classical");
    expect(signature.verdict.status).toBe("act-now");
  });

  it.each(["md2WithRSAEncryption", "md5WithRSAEncryption", "sha1WithRSAEncryption", "ecdsaWithSHA1", "dsaWithSHA1", "RC4", "DES-CBC", "3DES", "JWT-none"])(
    "treats %s as classically broken",
    (algorithm) => {
      expect(classifyThreat(finding({ algorithm }))).toBe("classical");
    },
  );

  it.each(["sha256WithRSAEncryption", "ecdsaWithSHA384", "ML-DSA-65", "AES-256-GCM", "SLH-DSA-SHA2-128s"])(
    "does not treat %s as classically broken",
    (algorithm) => {
      expect(classifyThreat(finding({ algorithm }))).not.toBe("classical");
    },
  );

  it("treats a structured obsolete TLS version as classical", () => {
    const obsolete = finding({ ruleId: "tls/negotiated-protocol", protocol: { type: "tls", version: "1.0" } });
    expect(classifyThreat(obsolete)).toBe("classical");
    expect(classifyThreat(finding({ ruleId: "tls/negotiated-protocol" }))).toBe("harvest-now");
  });
});

describe("migration-time assumptions (Mosca's Y)", () => {
  it("uses documented multi-year defaults, longer for signatures than for key establishment", () => {
    const profile = defaultProfile(TODAY);
    expect(profile.migrationYears.byThreat?.["harvest-now"]).toBe(3);
    expect(profile.migrationYears.byThreat?.["forge-later"]).toBe(5);
    expect(profile.migrationYears.basis).toMatch(/NCSC/);
    expect(DEFAULT_MIGRATION_YEARS.basis).toMatch(/Assumption/);
    const risk = assessRisk("h", [finding({ ruleId: "tls/hybrid-kex" }), finding({ id: "S", ruleId: "tls/leaf-signature", algorithm: "sha256WithRSAEncryption" })], profile);
    expect(risk.assets.map((a) => a.verdict.migrationYears)).toEqual([3, 5]);
    expect(risk.assumptions.migrationYears.basis).toMatch(/NCSC/);
  });

  it("documents the CRQC default as an assumption with its planning sources", () => {
    const { quantum } = defaultProfile(TODAY);
    expect(quantum.crqcYear).toBe(2035);
    expect(quantum.basis).toMatch(/^Assumption, not a forecast/);
    expect(quantum.basis).toMatch(/NSM-10/);
    expect(quantum.basis).toMatch(/IR 8547/);
  });

  it("puts general-business key exchange on an overdue path with the defaults (X + Y > Z)", () => {
    // 2026-01-01: Z = 9, X = 7, Y = 3, so X + Y = 10 > 9. The old 1-year default called this on-track.
    const risk = assessRisk("h", [finding({ ruleId: "tls/hybrid-kex" })], defaultProfile(TODAY));
    expect(risk.assets[0]?.verdict.status).toBe("overdue");
    expect(risk.assets[0]?.verdict.rationale).toMatch(/X \+ Y > Z/);
  });

  it("accepts a uniform override", () => {
    const profile = defaultProfile(TODAY, { migrationYears: 1 });
    const risk = assessRisk("h", [finding({ ruleId: "tls/hybrid-kex" })], profile);
    expect(risk.assets[0]?.verdict.migrationYears).toBe(1);
    expect(risk.assets[0]?.verdict.status).toBe("on-track");
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, 1000, 99999])("rejects an unusable CRQC year (%s)", (crqcYear) => {
    expect(() => defaultProfile(TODAY, { crqcYear })).toThrow(RangeError);
  });

  it.each([0, -1, Number.NaN, 500])("rejects an unusable migration time (%s)", (migrationYears) => {
    expect(() => defaultProfile(TODAY, { migrationYears })).toThrow(RangeError);
  });

  it("rejects a hand-built profile with NaN inputs instead of calling it on-track", () => {
    const profile = { ...defaultProfile(TODAY), quantum: { crqcYear: Number.NaN, basis: "x" } };
    expect(() => assessRisk("h", [finding({ ruleId: "tls/hybrid-kex" })], profile)).toThrow(RangeError);
  });

  it("gives every default combination a verdict consistent with the Mosca inequality", () => {
    const today = fractional(TODAY);
    const findings = [
      finding({ id: "kex", ruleId: "tls/hybrid-kex" }),
      finding({ id: "sig", ruleId: "tls/leaf-signature", algorithm: "sha256WithRSAEncryption" }),
      finding({ id: "dual", category: "source", ruleId: "source/rsa", algorithm: "RSA-3072" }),
    ];
    for (const crqcYear of [2026, 2028, 2030, 2033, 2035, 2040, 2050]) {
      for (const dataClass of DATA_CLASSES) {
        const profile = defaultProfile(TODAY, { dataClassId: dataClass.id, crqcYear });
        const z = crqcYear - today;
        for (const asset of assessRisk("h", findings, profile).assets) {
          const { threat, status, horizonYears: x, migrationYears: y } = asset.verdict;
          const where = `${dataClass.id} ${crqcYear} ${asset.key}: ${threat} ${status}`;
          expect(Number.isFinite(y) && y > 0, where).toBe(true);
          if (threat === "harvest-now") {
            // Public data (X = 0) has nothing to harvest; everything else follows X, Y, Z.
            expect(status, where).toBe(x <= 0 ? "not-applicable" : x > z ? "exposed" : x + y > z ? "overdue" : "on-track");
          } else {
            expect(threat, where).toBe("forge-later");
            expect(status, where).toBe(z <= 0 ? "exposed" : y > z ? "overdue" : "on-track");
          }
          expect(asset.verdict.rationale, where).not.toMatch(/NaN/);
        }
      }
    }
  });
});

function fractional(iso: string): number {
  const date = new Date(iso);
  const year = date.getUTCFullYear();
  return year + (date.getTime() - Date.UTC(year, 0, 1)) / (Date.UTC(year + 1, 0, 1) - Date.UTC(year, 0, 1));
}
