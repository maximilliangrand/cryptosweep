import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { CertInfo } from "../src/scanners/tls";
import { analyzeTls, parseCertificate } from "../src/scanners/tls";
import { REFS } from "../src/crypto";
import type { Finding } from "../src/report";

function fixture(path: string): Buffer {
  return readFileSync(fileURLToPath(new URL(`./fixtures/${path}`, import.meta.url)));
}

function parsed(path: string, isLeaf = true): CertInfo {
  const info = parseCertificate(fixture(path), isLeaf);
  if (!info) throw new Error(`fixture ${path} did not parse`);
  return info;
}

function byId(findings: Finding[], id: string): Finding {
  const finding = findings.find((f) => f.id === id);
  if (!finding) throw new Error(`expected finding ${id}, got ${findings.map((f) => f.id).join(", ")}`);
  return finding;
}

const NOW = new Date("2026-01-01T00:00:00.000Z");

function analyzeChain(chain: CertInfo[]): Finding[] {
  return analyzeTls({ protocol: "TLSv1.3", cipherName: null, groupName: "X25519", chain }, "pq.example.com:443", NOW);
}

describe("parseCertificate: post-quantum and unusual keys", () => {
  it("types an ML-DSA-65 leaf as a post-quantum key, not unknown-key", () => {
    const info = parsed("tls-server/ml-dsa-65-cert.pem");
    expect(info.keyType).toBe("ml-dsa-65");
    expect(info.keyOid).toBe("2.16.840.1.101.3.4.3.18");
    expect(info.signatureAlgorithm).toBe("ML-DSA-65");

    const key = byId(analyzeChain([info]), "CSW-TLS-001");
    expect(key.title).toBe("Leaf public key: ML-DSA-65");
    expect(key.pq_status).toBe("safe");
    expect(key.severity).toBe("info");
    expect(key.confidence).toBe("confirmed");
    expect(key.recommendation).toMatch(/does not meet CNSA 2\.0/);
  });

  it("types an SLH-DSA leaf as a post-quantum key", () => {
    const info = parsed("tls-certs/slh-dsa-sha2-128s.pem");
    expect(info.keyType).toBe("slh-dsa-sha2-128s");
    expect(byId(analyzeChain([info]), "CSW-TLS-001").pq_status).toBe("safe");
  });

  it("falls back to the SPKI OID when the runtime cannot decode a post-quantum key", () => {
    // SPKI says ML-DSA-65 but carries 65 bytes of key: Node throws on
    // `x509.publicKey`, exactly as an OpenSSL without ML-DSA would.
    const info = parsed("tls-certs/ml-dsa-65-undecodable-key.pem");
    expect(info.keyType).toBe("ml-dsa-65");
    expect(info.keyOid).toBe("2.16.840.1.101.3.4.3.18");
  });

  it("never throws on an unknown public-key algorithm, and keeps its OID", () => {
    const der = fixture("tls-certs/unknown-spki.pem");
    expect(() => parseCertificate(der, true)).not.toThrow();
    const info = parsed("tls-certs/unknown-spki.pem");
    expect(info.keyType).toBe("unknown");
    expect(info.keyOid).toBe("1.2.840.10045.2.127");
    expect(info.signatureAlgorithm).toBe("ecdsaWithSHA256");
  });
});

describe("parseCertificate: RSASSA-PSS digest", () => {
  it("reads an absent PSS hashAlgorithm as its SHA-1 default and flags it", () => {
    const info = parsed("tls-certs/pss-sha1-default.pem");
    expect(info.signatureOid).toBe("1.2.840.113549.1.1.10");
    expect(info.signatureAlgorithm).toBe("rsassaPss-sha1");
    const sig = byId(analyzeChain([info]), "CSW-TLS-002");
    expect(sig.severity).toBe("high");
    expect(sig.recommendation).toMatch(/SHA-1/);
  });

  it("names the PSS digest when it is explicit", () => {
    const info = parsed("tls-certs/pss-sha256.pem");
    expect(info.signatureAlgorithm).toBe("rsassaPss-sha256");
    expect(byId(analyzeChain([info]), "CSW-TLS-002").severity).toBe("medium");
  });
});

describe("intermediate certificates", () => {
  const leaf = parsed("tls-server/sha1-chain-leaf-cert.pem");

  it("flags a SHA-1-signed intermediate, not only a SHA-1 leaf", () => {
    const intermediate = parsed("tls-certs/sha1-intermediate.pem", false);
    expect(intermediate.signatureAlgorithm).toBe("sha1WithRSAEncryption");
    const findings = analyzeChain([leaf, intermediate]);
    const sig = byId(findings, "CSW-TLS-006");
    expect(sig.ruleId).toBe("tls/intermediate-signature");
    expect(sig.severity).toBe("high");
    expect(sig.evidence).toContain("Cryptosweep Test SHA1 Intermediate");
    // The leaf itself is SHA-256: the only SHA-1 is one level up.
    expect(byId(findings, "CSW-TLS-002").severity).toBe("medium");
  });

  it("does not raise a separate finding for a sound classical intermediate signature", () => {
    const intermediate: CertInfo = { ...parsed("tls-certs/sha1-intermediate.pem", false), signatureAlgorithm: "sha256WithRSAEncryption" };
    expect(analyzeChain([leaf, intermediate]).some((f) => f.id === "CSW-TLS-006")).toBe(false);
  });

  it("recognizes an ML-DSA intermediate key but still sees its classical signature", () => {
    const intermediate = parsed("tls-certs/ml-dsa-intermediate.pem", false);
    expect(intermediate.keyType).toBe("ml-dsa-65");
    const chain = byId(analyzeChain([leaf, intermediate]), "CSW-TLS-003");
    expect(chain.title).not.toMatch(/unrecognized/);
    // Signed by an RSA root, so a quantum computer could still forge this link.
    expect(chain.pq_status).toBe("vulnerable");
    expect(chain.evidence).toContain("ML-DSA-65 key, sha256WithRSAEncryption signature");
  });

  it("reports an all-post-quantum chain as safe", () => {
    const intermediate: CertInfo = { ...parsed("tls-certs/ml-dsa-intermediate.pem", false), signatureAlgorithm: "ML-DSA-87" };
    const chain = byId(analyzeChain([leaf, intermediate]), "CSW-TLS-003");
    expect(chain.pq_status).toBe("safe");
    expect(chain.severity).toBe("info");
  });
});

describe("leaf key recommendations", () => {
  const base = parsed("tls-server/rsa2048-cert.pem");

  it("states the IR 8547 deprecation date for a 112-bit RSA-2048 key", () => {
    const key = byId(analyzeChain([base]), "CSW-TLS-001");
    expect(key.recommendation).toMatch(/after 2030/);
  });

  it("says DSA is withdrawn for signature generation (FIPS 186-5)", () => {
    const key = byId(analyzeChain([{ ...base, keyType: "dsa" }]), "CSW-TLS-001");
    expect(key.recommendation).toMatch(/FIPS 186-5/);
    expect(key.references).toContain(REFS.fips1865);
  });
});
