import { describe, expect, it } from "vitest";
import type { Finding } from "../src/report";
import { defaultProfile } from "../src/model/estate";
import { assessRisk, classifyThreat } from "../src/model/risk";

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
