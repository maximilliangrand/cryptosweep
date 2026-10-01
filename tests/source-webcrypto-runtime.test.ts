/**
 * WebCrypto calls whose algorithm is computed at runtime. jose 6.x implements
 * RS/PS/ES/EdDSA, RSA-OAEP and ECDH-ES entirely through `crypto.subtle` with
 * computed algorithms, and used to scan to zero findings with complete
 * coverage. Each such call now gets an `info` marker, as jsonwebtoken calls
 * with a runtime algorithm already did.
 */
import { describe, expect, it } from "vitest";
import { scanContent } from "../src/scanners/source";

/** The shape of jose's webapi/lib/signing.js and ecdhes.js. */
const JOSE_LIKE = `
import subtleAlgorithm from './subtle_dsa.js';
import getSignKey from './get_sign_verify_key.js';

export async function sign(alg, key, data) {
  const cryptoKey = await getSignKey(alg, key, 'sign');
  const signature = await crypto.subtle.sign(subtleAlgorithm(alg, cryptoKey.algorithm), cryptoKey, data);
  return new Uint8Array(signature);
}

export async function deriveKey(publicKey, privateKey, keyLength) {
  return new Uint8Array(await crypto.subtle.deriveBits({ name: publicKey.algorithm.name, public: publicKey }, privateKey, keyLength));
}

export async function generate(alg, options) {
  return crypto.subtle.generateKey(algorithmFor(alg, options), options?.extractable ?? false, ['sign', 'verify']);
}
`;

const unresolved = (path: string, code: string) =>
  scanContent(path, code).filter((f) => f.ruleId === "source/webcrypto/algorithm-unresolved");

describe("WebCrypto calls with a runtime algorithm", () => {
  it("are reported as info markers, one per call site", () => {
    const findings = unresolved("dist/webapi/lib/signing.js", JOSE_LIKE);
    expect(findings.map((f) => f.title)).toEqual([
      "WebCrypto call with an algorithm chosen at runtime (sign, algorithm set at runtime)",
      "WebCrypto call with an algorithm chosen at runtime (deriveBits, algorithm set at runtime)",
      "WebCrypto call with an algorithm chosen at runtime (generateKey, algorithm set at runtime)",
    ]);
    for (const f of findings) {
      expect(f).toMatchObject({ severity: "info", pq_status: "unknown", confidence: "confirmed" });
    }
  });

  it("are not reported for a static algorithm, symmetric or asymmetric", () => {
    const code = [
      'crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);',
      'const params = { name: "HMAC", hash: "SHA-256" };',
      "crypto.subtle.sign(params, key, data);",
      'crypto.subtle.sign("Ed25519", key, data);',
    ].join("\n");
    expect(unresolved("src/a.js", code)).toEqual([]);
    expect(scanContent("src/a.js", code).map((f) => f.ruleId)).toEqual(["source/webcrypto/eddsa"]);
  });

  it("are not guessed by the regex fallback, which cannot tell a runtime algorithm from AES", () => {
    const broken = 'crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);\ncrypto.subtle.sign(alg, key, data);\n} broken';
    expect(unresolved("src/broken.js", broken)).toEqual([]);
  });
});
