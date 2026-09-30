import { performance } from "node:perf_hooks";
import { describe, expect, it } from "vitest";
import { scanContent } from "../src/scanners/source";
import { JS_CALL_MATCHERS, REGEX_MATCHERS, SOURCE_RULES } from "../src/scanners/source-rules";
import type { RegexLanguage } from "../src/scanners/source-rules";

const FILE_FOR: Record<RegexLanguage, string> = {
  javascript: "page.html", // non-JS files get the JavaScript regex sweep
  python: "app.py",
  go: "main.go",
  java: "App.java",
};

/**
 * Snippets for rules the regex samples do not reach: the JS/TS AST rules and
 * rule variants a sample cannot show on its own.
 */
const SNIPPETS: ReadonlyArray<readonly [file: string, code: string, rule: string]> = [
  ["a.js", 'const c = require("crypto");\nc.generateKeyPairSync("rsa", { modulusLength: 2048 });', "source/node-crypto/keygen-rsa"],
  ["a.js", 'const c = require("crypto");\nc.generateKeyPairSync("dsa", { modulusLength: 2048 });', "source/node-crypto/keygen-dsa"],
  ["a.js", 'const c = require("crypto");\nc.generateKeyPairSync("ec", { namedCurve: "P-256" });', "source/node-crypto/keygen-ec"],
  ["a.js", 'const c = require("crypto");\nc.generateKeyPair("ed448", cb);', "source/node-crypto/keygen-eddsa"],
  ["a.js", 'const c = require("crypto");\nc.generateKeyPairSync("x448");', "source/node-crypto/keygen-xdh"],
  ["a.js", 'const c = require("crypto");\nc.generateKeyPairSync("dh", { group: "modp14" });', "source/node-crypto/keygen-dh"],
  ["a.js", 'const c = require("crypto");\nc.createVerify("sha256");', "source/node-crypto/signature"],
  ["a.js", 'const c = require("crypto");\nc.createECDH("secp384r1");', "source/node-crypto/ecdh"],
  ["a.js", 'const c = require("crypto");\nc.createDiffieHellmanGroup("modp14");', "source/node-crypto/dh"],
  ["a.js", 'const c = require("crypto");\nc.diffieHellman({ privateKey, publicKey });', "source/node-crypto/key-agreement"],
  ["a.js", 'const c = require("crypto");\nc.privateDecrypt(key, buf);', "source/node-crypto/rsa-encryption"],
  ["a.js", 'const c = require("crypto");\nc.privateEncrypt(key, buf);', "source/node-crypto/rsa-private-encrypt"],
  ["a.js", 'const c = require("crypto");\nc.hash("sha1", data);', "source/node-crypto/weak-hash"],
  ["a.js", 'const c = require("crypto");\nconst etag = c.createHash("md5").update(b).digest("hex");', "source/node-crypto/weak-hash-non-security"],
  ["a.js", 'const c = require("crypto");\nc.createDecipheriv("rc2-cbc", k, iv);', "source/node-crypto/weak-cipher"],
  ["a.js", 'const c = require("crypto");\nc.pbkdf2Sync(pw, salt, 1000, 32, "sha1");', "source/node-crypto/legacy-digest"],
  ["a.js", 'crypto.subtle.generateKey({ name: "RSA-PSS", modulusLength: 3072 }, true, ["sign"]);', "source/webcrypto/keygen-rsa"],
  ["a.js", 'crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);', "source/webcrypto/keygen-ec"],
  ["a.js", 'crypto.subtle.importKey("raw", bytes, "Ed25519", true, ["verify"]);', "source/webcrypto/keygen-eddsa"],
  ["a.js", 'crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);', "source/webcrypto/keygen-xdh"],
  ["a.js", 'crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, data);', "source/webcrypto/rsa-signature"],
  ["a.js", 'crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, data);', "source/webcrypto/ecdsa"],
  ["a.js", 'crypto.subtle.sign({ name: "Ed25519" }, key, data);', "source/webcrypto/eddsa"],
  ["a.js", 'crypto.subtle.deriveKey({ name: "X25519", public: peer }, priv, aes, false, ["encrypt"]);', "source/webcrypto/key-agreement"],
  ["a.js", 'crypto.subtle.wrapKey("raw", key, wrapper, { name: "RSA-OAEP" });', "source/webcrypto/rsa-oaep"],
  ["a.js", 'const jwt = require("jsonwebtoken");\njwt.sign(p, k, { algorithm: "none" });', "jwt/jsonwebtoken/alg-none"],
  ["a.js", 'const jwt = require("jsonwebtoken");\njwt.sign(p, k, { algorithm: "HS256" });', "jwt/jsonwebtoken/hmac"],
  ["a.js", 'const jwt = require("jsonwebtoken");\njwt.sign(p, k, { algorithm: "PS384" });', "jwt/jsonwebtoken/rsa"],
  ["a.js", 'const jwt = require("jsonwebtoken");\njwt.verify(t, k, { algorithms: ["ES512"] });', "jwt/jsonwebtoken/ecdsa"],
  ["a.js", 'const jwt = require("jsonwebtoken");\njwt.verify(t, k, { algorithms: ["EdDSA"] });', "jwt/jsonwebtoken/eddsa"],
  ["a.js", 'const jwt = require("jsonwebtoken");\njwt.verify(t, k);', "jwt/jsonwebtoken/algorithm-unresolved"],
  ["a.js", 'import { UnsecuredJWT } from "jose";\nnew UnsecuredJWT(c).encode();', "jwt/jose/alg-none"],
  ["a.js", 'import { generateSecret } from "jose";\ngenerateSecret("HS256");', "jwt/jose/hmac"],
  ["a.js", 'import { jwtVerify } from "jose";\njwtVerify(t, k, { algorithms: ["RS256"] });', "jwt/jose/rsa"],
  ["a.js", 'import { SignJWT } from "jose";\nnew SignJWT(c).setProtectedHeader({ alg: "ES256" });', "jwt/jose/ecdsa"],
  ["a.js", 'import * as jose from "jose";\njose.generateKeyPair("EdDSA");', "jwt/jose/eddsa"],
  ["a.js", 'import { CompactEncrypt } from "jose";\nnew CompactEncrypt(b).setProtectedHeader({ alg: "RSA-OAEP", enc: "A256GCM" });', "jwt/jose/rsa-key-transport"],
  ["a.js", 'import { jwtDecrypt } from "jose";\njwtDecrypt(t, k, { keyManagementAlgorithms: ["ECDH-ES+A256KW"] });', "jwt/jose/ecdh-key-agreement"],
  ["a.js", 'import { SignJWT } from "jose";\nnew SignJWT(c).setProtectedHeader({ alg: process.env.ALG });', "jwt/jose/algorithm-unresolved"],
  ["a.py", 'import jwt\njwt.decode(t, k, algorithms=["none"])', "jwt/pyjwt/alg-none"],
  ["a.py", 'import jwt\njwt.encode(p, k, algorithm="HS384")', "jwt/pyjwt/hmac"],
  ["a.py", 'import jwt\njwt.encode(p, k, algorithm="EdDSA")', "jwt/pyjwt/eddsa"],
  ["a.py", "import hashlib\nhashlib.sha1(b, usedforsecurity=False)", "source/python-hashlib/weak-hash-non-security"],
  ["A.java", 'KeyPairGenerator.getInstance("EC");', "source/java/keygen-ec"],
  ["A.java", 'KeyPairGenerator.getInstance("DSA");', "source/java/keygen-dsa"],
  ["A.java", 'KeyPairGenerator.getInstance("DiffieHellman");', "source/java/keygen-dh"],
  ["A.java", 'KeyPairGenerator.getInstance("Ed25519");', "source/java/keygen-eddsa"],
  ["A.java", 'KeyPairGenerator.getInstance("X25519");', "source/java/keygen-xdh"],
  ["A.java", 'Signature.getInstance("SHA256withRSA");', "source/java/rsa-signature"],
  ["A.java", 'Signature.getInstance("SHA256withDSA");', "source/java/dsa-signature"],
  ["A.java", 'Signature.getInstance("Ed25519");', "source/java/eddsa"],
  ["A.java", 'Cipher.getInstance("RC4");', "source/java/weak-cipher"],
  ["k.txt", `-----BEGIN PRIVATE KEY-----\n${"A".repeat(64)}\n-----END PRIVATE KEY-----`, "keys/private-key-block"],
  ["k.txt", `-----BEGIN PUBLIC KEY-----\n${"A".repeat(64)}\n-----END PUBLIC KEY-----`, "keys/public-key-block"],
];

describe("rule catalogue", () => {
  it("has unique ids whose namespace matches the category", () => {
    const ids = SOURCE_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const rule of SOURCE_RULES) {
      const prefix = rule.id.split("/")[0];
      const expected = rule.category === "source" ? "source" : rule.category === "jwt" ? "jwt" : "keys";
      expect(prefix, rule.id).toBe(expected);
    }
  });

  it("documents every rule, and cites a NIST PQC standard for every Shor-vulnerable one", () => {
    for (const rule of SOURCE_RULES) {
      expect(rule.title.length, rule.id).toBeGreaterThan(0);
      expect(rule.primitive.length, rule.id).toBeGreaterThan(0);
      expect(rule.recommendation.length, rule.id).toBeGreaterThan(0);
      const asymmetric = rule.pq === "vulnerable" && ["key-generation", "signing", "key-agreement", "encryption"].includes(rule.usage);
      if (asymmetric && rule.primitive !== "DES/3DES/RC4/RC2" && rule.primitive !== "none") {
        expect(rule.references.map((r) => r.label).join(" "), rule.id).toMatch(/FIPS 20[34]/);
      }
    }
  });

  it("keeps regex-matched languages below AST confidence", () => {
    for (const rule of SOURCE_RULES.filter((r) => r.language === "python" || r.language === "go" || r.language === "java")) {
      expect(rule.confidence, rule.id).toBe("medium");
    }
  });

  it("has well-formed matchers (global patterns, non-global gates)", () => {
    for (const matcher of REGEX_MATCHERS) {
      expect(matcher.pattern.global, matcher.pattern.source).toBe(true);
      if (matcher.gate) expect(matcher.gate.global, matcher.gate.source).toBe(false);
    }
    for (const matcher of JS_CALL_MATCHERS) expect(matcher.methods.length).toBeGreaterThan(0);
  });

  it("fires every regex matcher on its own sample", () => {
    for (const matcher of REGEX_MATCHERS) {
      const findings = scanContent(FILE_FOR[matcher.language], matcher.sample);
      const known = findings.filter((f) => SOURCE_RULES.some((r) => r.id === f.ruleId));
      expect(known.length, `${matcher.language}: ${matcher.sample}`).toBeGreaterThan(0);
    }
  });

  it("has no dead rules: every detection rule is produced by some sample", () => {
    const produced = new Set<string>();
    for (const matcher of REGEX_MATCHERS) {
      for (const f of scanContent(FILE_FOR[matcher.language], matcher.sample)) if (f.ruleId) produced.add(f.ruleId);
    }
    for (const [file, code, rule] of SNIPPETS) {
      const rules = scanContent(file, code).map((f) => f.ruleId);
      expect(rules, `${rule}: ${code}`).toContain(rule);
      produced.add(rule);
    }
    const dead = SOURCE_RULES.filter((r) => r.usage !== "coverage" && !produced.has(r.id)).map((r) => r.id);
    expect(dead).toEqual([]);
  });
});

describe("ReDoS: every regex in the rule table", () => {
  const BUDGET_MS = 1_000;

  /**
   * Generic shapes plus, for each quote/paren/separator cut of the sample, the
   * sample's own tokens repeated after the cut: the shape that makes two
   * overlapping quantifiers around a middle token backtrack (the old
   * weak-cipher pattern went quadratic on `createCipher("desdesdes...`).
   */
  function adversarialInputs(sample: string): string[] {
    const size = 200_000;
    const half = sample.slice(0, Math.max(1, Math.floor(sample.length / 2)));
    const inputs = [
      sample.replace(/\s+/g, " ".repeat(20_000)),
      half.repeat(Math.ceil(100_000 / half.length)),
      sample.repeat(Math.ceil(100_000 / sample.length)),
      `${sample.slice(0, 24)}${"\n".repeat(50_000)}`,
      `${sample.slice(0, 24)}${"a".repeat(50_000)}`,
      `${sample.slice(0, 24)}${'"'.repeat(50_000)}`,
    ];
    const tokens = [...new Set(sample.split(/[\s"'`(),;{}[\]=:]+/).filter((t) => t.length > 0))].slice(0, 12);
    const cuts = [...sample.matchAll(/["'`([{=,:]/g)].map((m) => (m.index ?? 0) + 1).slice(0, 6);
    for (const cut of cuts) {
      for (const token of tokens) inputs.push(sample.slice(0, cut) + token.repeat(Math.ceil(size / token.length)));
    }
    return inputs;
  }

  function exhaust(pattern: RegExp, input: string): void {
    const regex = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;
    while ((match = regex.exec(input)) !== null) {
      if (match.index === regex.lastIndex) regex.lastIndex += 1;
    }
  }

  it("matches and gates run in linear time on hostile input", () => {
    for (const matcher of REGEX_MATCHERS) {
      for (const input of adversarialInputs(matcher.sample)) {
        const start = performance.now();
        exhaust(matcher.pattern, input);
        if (matcher.gate) matcher.gate.test(input);
        const elapsed = performance.now() - start;
        expect(elapsed, `${matcher.pattern.source} on ${input.length} chars`).toBeLessThan(BUDGET_MS);
      }
    }
  });

  it("scans a hostile file in every language end to end within budget", () => {
    for (const language of Object.keys(FILE_FOR) as RegexLanguage[]) {
      const samples = REGEX_MATCHERS.filter((m) => m.language === language).map((m) => m.sample).join("\n");
      const hostile = `${samples}\n${samples.replace(/\s+/g, " ".repeat(5_000))}`;
      const start = performance.now();
      scanContent(FILE_FOR[language], hostile);
      expect(performance.now() - start, language).toBeLessThan(BUDGET_MS * 2);
    }
  });
});
