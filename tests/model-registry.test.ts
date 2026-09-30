import { describe, expect, it } from "vitest";
import { REGISTRY, depsRuleId, entryForRuleId, lookupEntry } from "../src/scanners/deps/registry";
import { matchDeps } from "../src/scanners/deps";

describe("registry facts", () => {
  it("dates rustls post-quantum support to 0.23.22, not 0.23.0", () => {
    expect(lookupEntry("rustls", "cargo")?.fixedIn).toBe("0.23.22");
    const rustls = (version: string) =>
      matchDeps([{ name: "rustls", version, ecosystem: "cargo", manifestPath: "Cargo.toml" }])[0];
    // 0.23.5 (2024-04) predates FIPS 203 and shipped no X25519MLKEM768.
    expect(rustls("0.23.5")?.pq_status).toBe("vulnerable");
    expect(rustls("0.23.21")?.pq_status).toBe("vulnerable");
    expect(rustls("0.23.22")?.pq_status).toBe("transitional");
    expect(rustls("0.23.27")?.pq_status).toBe("transitional");
  });

  it("names the Open Quantum Safe Python bindings as published on PyPI", () => {
    expect(lookupEntry("oqs-python", "python")).toBeUndefined();
    expect(lookupEntry("liboqs-python", "python")?.pq_status).toBe("transitional");
  });

  it("does not call liboqs-based bindings pre-NIST-final", () => {
    for (const name of ["oqs", "pqcrypto"]) {
      expect(lookupEntry(name, "cargo")?.reason, name).not.toMatch(/pre-NIST|pre-standard/i);
    }
    expect(lookupEntry("liboqs-python", "python")?.reason).not.toMatch(/pre-NIST/i);
  });

  it("does not recommend one Shor-broken signature scheme as the migration from another", () => {
    for (const [name, ecosystem] of [["jsonwebtoken", "npm"], ["pyjwt", "python"], ["python-jose", "python"]] as const) {
      const recommendation = lookupEntry(name, ecosystem)?.recommendation ?? "";
      expect(recommendation, name).not.toMatch(/^Prefer .*(EdDSA|RSA-PSS)/);
      expect(recommendation, name).toMatch(/ML-DSA/);
      expect(recommendation, name).toMatch(/RFC 9964/);
    }
  });

  it("names a NIST PQ algorithm in every recommendation for a vulnerable asymmetric library", () => {
    const missing = REGISTRY.filter(
      (e) => e.pq_status === "vulnerable" && !/ML-KEM|ML-DSA|SLH-DSA|post-quantum|X25519MLKEM768/.test(e.recommendation),
    );
    expect(missing.map((e) => `${e.ecosystem}:${e.name}`)).toEqual([]);
  });

  it("does not describe paramiko key exchange as waiting for OpenSSH", () => {
    const paramiko = lookupEntry("paramiko", "python");
    expect(paramiko?.recommendation).not.toMatch(/until PQ KEX is GA/);
    expect(paramiko?.fixedIn).toBeUndefined(); // mlkem768x25519 support is unreleased as of 5.0.0
  });

  it("drops bcryptjs, a password hash with no quantum relevance", () => {
    expect(lookupEntry("bcryptjs", "npm")).toBeUndefined();
  });

  it("does not mark symmetric-only crypto-js as Shor-vulnerable", () => {
    expect(lookupEntry("crypto-js", "npm")?.pq_status).toBe("unknown");
  });

  it("dates cryptography's ML-KEM/ML-DSA availability in standard wheels to 48.0.0", () => {
    expect(lookupEntry("cryptography", "python")?.fixedIn).toBe("48.0.0");
  });
});

describe("registry structure", () => {
  it("records usage and algorithms for every entry", () => {
    for (const entry of REGISTRY) {
      const where = `${entry.ecosystem}:${entry.name}`;
      expect(entry.usage.length, where).toBeGreaterThan(0);
      expect(entry.algorithms.length, where).toBeGreaterThan(0);
    }
  });

  it("marks every library that encrypts or establishes keys as a harvest-now exposure", () => {
    const confidentiality = ["tweetnacl", "pynacl", "openpgp", "node-rsa", "elliptic", "x25519-dalek", "rsa", "node-forge"];
    for (const entry of REGISTRY.filter((e) => confidentiality.includes(e.name))) {
      expect(entry.usage.some((u) => u === "encryption" || u === "key-establishment"), entry.name).toBe(true);
    }
  });

  it("round-trips rule ids exactly, without parsing names out of them", () => {
    for (const entry of REGISTRY) expect(entryForRuleId(depsRuleId(entry))).toBe(entry);
    expect(entryForRuleId("deps/npm-")).toBeUndefined();
    expect(entryForRuleId(undefined)).toBeUndefined();
  });

  it("matches the rule id the dependency scanner emits", () => {
    const [finding] = matchDeps([{ name: "tweetnacl", version: "1.0.3", ecosystem: "npm", manifestPath: "package.json" }]);
    expect(entryForRuleId(finding?.ruleId)?.name).toBe("tweetnacl");
  });
});
