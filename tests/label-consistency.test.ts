/**
 * One spelling per algorithm, and verdicts that match their subject:
 * PEM SLH-DSA keys were `SLH-DSA-SHA2-128S` while certificates said
 * `SLH-DSA-SHA2-128s` (two assets for one algorithm), JCA MD2 was labelled
 * MD5, leaked ML-DSA private keys were pq "vulnerable", IPv6 evidence was
 * unbracketed, and a TLS 1.3 protocol finding was "transitional".
 */
import { generateKeyPairSync } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";
import { keyAlgorithmLabel } from "../src/crypto";
import type { Finding } from "../src/report";
import { scanContent } from "../src/scanners/source";
import { analyzeTls, scanTls } from "../src/scanners/tls";
import type { TlsScanResult } from "../src/scanners/tls";

/** A key pair of `type`, or null when this runtime's OpenSSL does not implement it. */
function keyPair(type: string, options: Record<string, unknown> = {}): { publicKey: KeyObject; privateKey: KeyObject } | null {
  try {
    return (generateKeyPairSync as unknown as (t: string, o: Record<string, unknown>) => { publicKey: KeyObject; privateKey: KeyObject })(type, options);
  } catch {
    return null;
  }
}

const pemOf = (key: KeyObject, type: "spki" | "pkcs8"): string => String(key.export({ type, format: "pem" }));

const keyFinding = (pem: string): Finding | undefined => scanContent("keys/k.pem", pem).find((f) => f.category === "keys");

describe("key labels", () => {
  const slh = keyPair("slh-dsa-sha2-128s");
  it.skipIf(!slh)("labels a PEM SLH-DSA public key the way a certificate key is labelled", () => {
    if (!slh) return;
    expect(keyFinding(pemOf(slh.publicKey, "spki"))?.algorithm).toBe(keyAlgorithmLabel("slh-dsa-sha2-128s", null, null));
    expect(keyAlgorithmLabel("slh-dsa-sha2-128s", null, null)).toBe("SLH-DSA-SHA2-128s");
  });

  it("labels JCA MD2 as MD2", () => {
    const [md2] = scanContent("src/A.java", 'MessageDigest.getInstance("MD2");');
    expect(md2?.algorithm).toBe("MD2");
  });
});

describe("committed private keys", () => {
  it("are typed when their PEM parses, and stay critical", () => {
    const rsa = keyPair("rsa", { modulusLength: 2048 });
    if (!rsa) throw new Error("RSA key generation failed");
    const finding = keyFinding(pemOf(rsa.privateKey, "pkcs8"));
    expect(finding).toMatchObject({ ruleId: "keys/private-key-block", algorithm: "RSA-2048", severity: "critical", pq_status: "vulnerable" });
  });

  const mlDsa = keyPair("ml-dsa-65");
  it.skipIf(!mlDsa)("are not called quantum-vulnerable when the key is post-quantum", () => {
    if (!mlDsa) return;
    const finding = keyFinding(pemOf(mlDsa.privateKey, "pkcs8"));
    expect(finding).toMatchObject({ algorithm: "ML-DSA-65", severity: "critical", pq_status: "safe" });
    expect(finding?.recommendation).toMatch(/the leak, not the algorithm/);
  });

  it("stay untyped when encrypted", () => {
    const rsa = keyPair("rsa", { modulusLength: 2048 });
    if (!rsa) throw new Error("RSA key generation failed");
    const encrypted = String(rsa.privateKey.export({ type: "pkcs8", format: "pem", cipher: "aes-256-cbc", passphrase: "p" }));
    expect(keyFinding(encrypted)).toMatchObject({ severity: "critical", pq_status: "vulnerable" });
    expect(keyFinding(encrypted)?.algorithm).toBeUndefined();
  });
});

const RESULT: TlsScanResult = { protocol: "TLSv1.3", cipherName: "TLS_AES_256_GCM_SHA384", groupName: "X25519", chain: [] };

describe("TLS findings", () => {
  it("bracket an IPv6 host in the evidence", async () => {
    const findings = await scanTls("2606:4700:4700::1111", { probe: () => Promise.resolve(RESULT) });
    expect(findings.every((f) => f.evidence.startsWith("[2606:4700:4700::1111]:443"))).toBe(true);
    expect(findings[0]?.location).toEqual({ host: "2606:4700:4700::1111", port: 443 });
  });

  it("leave the post-quantum verdict of a TLS 1.3 session to its key exchange", () => {
    const protocol = analyzeTls(RESULT, "h:443", new Date()).find((f) => f.ruleId === "tls/negotiated-protocol");
    expect(protocol?.pq_status).toBe("unknown");
    expect(protocol?.recommendation).toMatch(/key-exchange finding/);
  });
});
