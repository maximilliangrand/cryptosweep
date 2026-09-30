import { describe, expect, it } from "vitest";
import {
  REFS,
  ir8547Transition,
  isPostQuantumKey,
  isQuantumVulnerableKey,
  keyAlgorithmLabel,
  keyPosture,
  meetsCnsa2,
  toKeyType,
} from "../src/crypto";

describe("key-type knowledge base", () => {
  it("calls only the listed classical types quantum-vulnerable (explicit allow list)", () => {
    for (const type of ["rsa", "rsa-pss", "dsa", "ec", "ed25519", "ed448"] as const) {
      expect(isQuantumVulnerableKey(type), type).toBe(true);
    }
    // The old predicate was `keyType !== "unknown"`, so every post-quantum type
    // added to the union would have been reported as vulnerable.
    for (const type of ["ml-dsa-65", "slh-dsa-sha2-128s", "ml-kem-1024", "unknown"] as const) {
      expect(isQuantumVulnerableKey(type), type).toBe(false);
    }
  });

  it("recognizes the FIPS 203/204/205 key types Node reports, and nothing else", () => {
    expect(toKeyType("ml-dsa-87")).toBe("ml-dsa-87");
    expect(toKeyType("slh-dsa-shake-256f")).toBe("slh-dsa-shake-256f");
    expect(toKeyType("ml-kem-768")).toBe("ml-kem-768");
    expect(toKeyType("x25519")).toBe("unknown");
    expect(toKeyType(undefined)).toBe("unknown");
    expect(isPostQuantumKey("ml-dsa-44")).toBe(true);
    expect(isPostQuantumKey("rsa")).toBe(false);
  });

  it("classifies post-quantum keys as safe with their FIPS citation", () => {
    const mlDsa = keyPosture("ml-dsa-65");
    expect(mlDsa.pq_status).toBe("safe");
    expect(mlDsa.severity).toBe("info");
    expect(mlDsa.references).toContain(REFS.fips204);
    expect(keyPosture("slh-dsa-sha2-128s").references).toContain(REFS.fips205);
    expect(keyPosture("ml-kem-1024").references).toContain(REFS.fips203);
    expect(keyPosture("unknown").pq_status).toBe("unknown");
  });

  it("labels post-quantum keys the way the standards write them", () => {
    expect(keyAlgorithmLabel("ml-dsa-65", null, null)).toBe("ML-DSA-65");
    expect(keyAlgorithmLabel("slh-dsa-sha2-128s", null, null)).toBe("SLH-DSA-SHA2-128s");
    expect(keyAlgorithmLabel("ml-kem-1024", null, null)).toBe("ML-KEM-1024");
  });

  it("knows which parameter sets CNSA 2.0 specifies", () => {
    expect(meetsCnsa2("ml-dsa-87")).toBe(true);
    expect(meetsCnsa2("ml-kem-1024")).toBe(true);
    expect(meetsCnsa2("ml-dsa-65")).toBe(false);
    expect(meetsCnsa2("slh-dsa-sha2-256s")).toBe(false);
  });

  it("encodes the IR 8547 draft schedule: 112-bit keys deprecated after 2030", () => {
    expect(ir8547Transition("rsa", 2048, null)).toEqual({ deprecatedAfter: 2030, disallowedAfter: 2035 });
    expect(ir8547Transition("rsa", 4096, null)).toEqual({ deprecatedAfter: null, disallowedAfter: 2035 });
    expect(ir8547Transition("ec", null, "P-224")).toEqual({ deprecatedAfter: 2030, disallowedAfter: 2035 });
    expect(ir8547Transition("ec", null, "P-384")).toEqual({ deprecatedAfter: null, disallowedAfter: 2035 });
    expect(ir8547Transition("ml-dsa-65", null, null)).toBeNull();
    expect(ir8547Transition("rsa", 1024, null)).toBeNull(); // already below the SP 800-131A floor
  });

  it("cites the draft that actually defines X25519MLKEM768", () => {
    expect(REFS.hybridKex.url).toContain("draft-ietf-tls-ecdhe-mlkem");
    expect(REFS.hybridKex.label).toContain("X25519MLKEM768");
    expect(REFS.hybridDesign.url).toContain("draft-ietf-tls-hybrid-design");
    expect(REFS.sp800131a.label).not.toMatch(/SHA-1/); // it is cited for key lengths too
  });
});
