import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { X509Certificate } from "node:crypto";
import { describe, expect, it } from "vitest";
import { certificateSignatureOid, signatureAlgorithmName } from "../src/asn1";

function der(name: string): Buffer {
  const pem = readFileSync(fileURLToPath(new URL(`./fixtures/certs/${name}.pem`, import.meta.url)));
  return Buffer.from(new X509Certificate(pem).raw);
}

describe("certificateSignatureOid", () => {
  it("reads the signatureAlgorithm OID from real certificates", () => {
    expect(certificateSignatureOid(der("rsa2048"))).toBe("1.2.840.113549.1.1.11");
    expect(certificateSignatureOid(der("ec-p256"))).toBe("1.2.840.10045.4.3.2");
    expect(certificateSignatureOid(der("ed25519"))).toBe("1.3.101.112");
    expect(certificateSignatureOid(der("rsa-sha1"))).toBe("1.2.840.113549.1.1.5");
    expect(certificateSignatureOid(der("rsa-md5"))).toBe("1.2.840.113549.1.1.4");
  });

  it("names the classically-broken digests instead of reporting them as unknown", () => {
    // An unrecognized OID reads as "nothing to see here", which is the worst
    // possible verdict on the worst algorithms in the corpus.
    expect(signatureAlgorithmName(certificateSignatureOid(der("rsa-md5")))).toBe("md5WithRSAEncryption");
    expect(signatureAlgorithmName("1.2.840.113549.1.1.2")).toBe("md2WithRSAEncryption");
  });

  it("does not confuse OIDs that merely appear inside the cert (parse, don't guess)", () => {
    // The old scanner used indexOf on the whole DER; the parser walks structure.
    // A SHA-256-RSA cert must never be misreported as anything else.
    expect(signatureAlgorithmName(certificateSignatureOid(der("rsa2048")))).toBe("sha256WithRSAEncryption");
  });

  it("returns null for empty, truncated, or non-DER input rather than throwing", () => {
    expect(certificateSignatureOid(undefined)).toBeNull();
    expect(certificateSignatureOid(Buffer.alloc(0))).toBeNull();
    expect(certificateSignatureOid(Buffer.from([0x30, 0x82, 0xff, 0xff]))).toBeNull(); // length past end
    expect(certificateSignatureOid(Buffer.from([0x02, 0x01, 0x00]))).toBeNull(); // not a SEQUENCE
    expect(certificateSignatureOid(der("rsa2048").subarray(0, 20))).toBeNull(); // truncated cert
  });
});

describe("signatureAlgorithmName", () => {
  it("maps known OIDs and passes through unknown ones as null", () => {
    expect(signatureAlgorithmName("1.3.101.112")).toBe("Ed25519");
    expect(signatureAlgorithmName("2.16.840.1.101.3.4.3.17")).toBe("ML-DSA-44");
    // All twelve SLH-DSA parameter sets, not just the first.
    expect(signatureAlgorithmName("2.16.840.1.101.3.4.3.26")).toBe("SLH-DSA-SHAKE-128s");
    expect(signatureAlgorithmName("2.16.840.1.101.3.4.3.31")).toBe("SLH-DSA-SHAKE-256f");
    expect(signatureAlgorithmName("9.9.9.9")).toBeNull();
    expect(signatureAlgorithmName(null)).toBeNull();
  });
});
