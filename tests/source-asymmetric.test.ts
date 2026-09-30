import { describe, expect, it } from "vitest";
import { scanContent } from "../src/scanners/source";
import type { Finding } from "../src/report";

/**
 * Shor-vulnerable asymmetric crypto in source. Before the rule table, every
 * call below produced zero findings and the report said "No quantum-vulnerable
 * primitives detected" for a repo full of RSA and ECDH.
 */
function byRule(findings: readonly Finding[], ruleId: string): Finding | undefined {
  return findings.find((f) => f.ruleId === ruleId);
}

describe("node:crypto asymmetric APIs", () => {
  const code = [
    'import crypto from "node:crypto";',
    'const { generateKeyPairSync, createECDH, createSign, publicEncrypt } = crypto;',
    'const weak = generateKeyPairSync("rsa", { modulusLength: 1024 });',
    'const ecdh = createECDH("prime256v1");',
    'const signer = createSign("RSA-SHA256");',
    "const ct = publicEncrypt(weak.publicKey, data);",
    "const dh = crypto.createDiffieHellman(512);",
    'const k1 = generateKeyPairSync("ec", { namedCurve: "secp256k1" });',
    'const ed = crypto.generateKeyPairSync("ed25519");',
    'const x = crypto.generateKeyPairSync("x25519");',
    'const grp = crypto.getDiffieHellman("modp2");',
    'const sig = crypto.sign("sha256", data, privateKey);',
    "const shared = crypto.diffieHellman({ privateKey, publicKey });",
    'const pq = crypto.generateKeyPairSync("ml-dsa-65");',
  ].join("\n");
  const findings = scanContent("src/app.ts", code);

  it("reports every classical call site, each with a stable rule id", () => {
    expect(findings.every((f) => typeof f.ruleId === "string" && f.ruleId.length > 0)).toBe(true);
    for (const rule of [
      "source/node-crypto/keygen-rsa",
      "source/node-crypto/ecdh",
      "source/node-crypto/signature",
      "source/node-crypto/rsa-encryption",
      "source/node-crypto/dh",
      "source/node-crypto/keygen-ec",
      "source/node-crypto/keygen-eddsa",
      "source/node-crypto/keygen-xdh",
      "source/node-crypto/key-agreement",
    ]) {
      expect(byRule(findings, rule), rule).toBeDefined();
    }
    expect(findings.every((f) => f.pq_status === "vulnerable")).toBe(true);
  });

  it("does not report a post-quantum key type", () => {
    expect(findings.some((f) => f.location?.line === 14)).toBe(false);
  });

  it("grades classical strength: sound keys are medium, sub-floor keys high or critical", () => {
    const rsa = byRule(findings, "source/node-crypto/keygen-rsa");
    expect(rsa?.algorithm).toBe("RSA-1024");
    expect(rsa?.severity).toBe("high");
    expect(rsa?.confidence).toBe("confirmed");
    const dh = findings.filter((f) => f.ruleId === "source/node-crypto/dh");
    expect(dh.find((f) => f.algorithm === "DH-512")?.severity).toBe("critical");
    expect(dh.find((f) => f.algorithm === "DH-1024")?.severity).toBe("high"); // modp2
    expect(byRule(findings, "source/node-crypto/ecdh")?.algorithm).toBe("ECDH-P-256");
    expect(byRule(findings, "source/node-crypto/ecdh")?.severity).toBe("medium");
    expect(byRule(findings, "source/node-crypto/keygen-ec")?.algorithm).toBe("ECDSA-secp256k1");
  });

  it("cites the NIST PQC standard that replaces each primitive", () => {
    const labels = (f: Finding | undefined) => (f?.references ?? []).map((r) => r.label).join(" ");
    expect(labels(byRule(findings, "source/node-crypto/signature"))).toMatch(/FIPS 204/);
    expect(labels(byRule(findings, "source/node-crypto/ecdh"))).toMatch(/FIPS 203/);
    expect(labels(byRule(findings, "source/node-crypto/keygen-rsa"))).toMatch(/SP 800-131A/); // 1024-bit
  });
});

describe("WebCrypto", () => {
  it("classifies key generation, import, signing, key agreement and encryption", () => {
    const code = [
      'await crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, publicExponent, hash: "SHA-256" }, true, ["encrypt"]);',
      'await crypto.subtle.importKey("spki", der, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);',
      'await crypto.subtle.sign({ name: "ECDSA", hash: { name: "SHA-384" } }, key, data);',
      'await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, priv, 256);',
      'await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, data);',
      'await crypto.subtle.generateKey("Ed25519", true, ["sign"]);',
      'await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);',
    ].join("\n");
    const f = scanContent("web/crypto.js", code);
    expect(byRule(f, "source/webcrypto/keygen-rsa")?.algorithm).toBe("RSA-2048");
    expect(byRule(f, "source/webcrypto/keygen-ec")?.algorithm).toBe("ECDSA-P-256");
    expect(byRule(f, "source/webcrypto/ecdsa")).toBeDefined();
    expect(byRule(f, "source/webcrypto/key-agreement")?.algorithm).toBe("ECDH");
    expect(byRule(f, "source/webcrypto/rsa-oaep")).toBeDefined();
    expect(byRule(f, "source/webcrypto/keygen-eddsa")?.algorithm).toBe("Ed25519");
    expect(f.some((x) => x.location?.line === 7)).toBe(false); // AES-GCM is not asymmetric
    expect(f.every((x) => x.confidence === "confirmed")).toBe(true); // the global crypto.subtle
  });
});

describe("JWT libraries", () => {
  it("covers jose, the library the registry recommends migrating to", () => {
    const code = [
      'import { SignJWT, jwtVerify, importPKCS8, EncryptJWT, UnsecuredJWT } from "jose";',
      'const token = await new SignJWT(claims).setIssuedAt().setProtectedHeader({ alg: "ES256" }).sign(key);',
      'await jwtVerify(token, key, { algorithms: ["RS256"] });',
      'const pk = await importPKCS8(pem, "PS256");',
      'const jwe = await new EncryptJWT(claims).setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" }).encrypt(pub);',
      "const unsigned = new UnsecuredJWT(claims).encode();",
    ].join("\n");
    const f = scanContent("auth/jose.ts", code);
    expect(byRule(f, "jwt/jose/ecdsa")?.confidence).toBe("confirmed");
    expect(byRule(f, "jwt/jose/rsa")).toBeDefined();
    expect(f.filter((x) => x.ruleId === "jwt/jose/rsa")).toHaveLength(2); // RS256 and PS256
    expect(byRule(f, "jwt/jose/rsa-key-transport")?.pq_status).toBe("vulnerable");
    expect(byRule(f, "jwt/jose/alg-none")?.severity).toBe("critical");
  });

  it("reports jsonwebtoken defaults and runtime-chosen algorithms instead of silently skipping them", () => {
    const code = [
      'const jwt = require("jsonwebtoken");',
      "jwt.sign(payload, secret);",
      "jwt.verify(token, publicKey);",
      "jwt.sign(payload, key, { algorithm: process.env.JWT_ALG });",
    ].join("\n");
    const f = scanContent("auth.js", code);
    const hmac = byRule(f, "jwt/jsonwebtoken/hmac");
    expect(hmac?.algorithm).toBe("JWT-HS256");
    expect(hmac?.confidence).toBe("high"); // the library default, not a literal
    const unresolved = f.filter((x) => x.ruleId === "jwt/jsonwebtoken/algorithm-unresolved");
    expect(unresolved).toHaveLength(2);
    expect(unresolved.every((x) => x.severity === "info" && x.pq_status === "unknown")).toBe(true);
  });

  it("rates HMAC as quantum-safe and words EdDSA correctly", () => {
    const f = scanContent("a.ts", 'import jwt from "jsonwebtoken";\njwt.sign(p, k, { algorithm: "HS512" });\njwt.verify(t, k, { algorithms: ["EdDSA"] });');
    expect(byRule(f, "jwt/jsonwebtoken/hmac")?.pq_status).toBe("safe");
    const eddsa = byRule(f, "jwt/jsonwebtoken/eddsa");
    expect(eddsa?.recommendation).toMatch(/Ed25519\/Ed448/);
    expect(eddsa?.recommendation).not.toMatch(/RSA\/ECDSA/);
  });
});

describe("Python (regex, comments stripped)", () => {
  it("covers pyca/cryptography, hashlib, PyCryptodome and PyJWT", () => {
    const code = [
      "import hashlib, jwt",
      "from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519, padding",
      "from Crypto.PublicKey import RSA",
      "key = rsa.generate_private_key(public_exponent=65537, key_size=1024)",
      "ek = ec.generate_private_key(ec.SECP256R1())",
      "shared = ek.exchange(ec.ECDH(), peer)",
      "xk = x25519.X25519PrivateKey.generate()",
      "ct = pub.encrypt(msg, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))",
      "old = RSA.generate(2048)",
      "digest = hashlib.md5(data).hexdigest()",
      'token = jwt.encode(payload, key, algorithm="RS256")',
      'claims = jwt.decode(token, key, algorithms=["ES256", "HS256"])',
    ].join("\n");
    const f = scanContent("svc/app.py", code);
    expect(byRule(f, "source/python-cryptography/keygen-rsa")?.severity).toBe("high"); // 1024-bit
    expect(byRule(f, "source/python-cryptography/keygen-ec")?.algorithm).toBe("ECDSA-P-256");
    expect(byRule(f, "source/python-cryptography/ecdh")).toBeDefined();
    expect(byRule(f, "source/python-cryptography/xdh")?.algorithm).toBe("X25519");
    expect(byRule(f, "source/python-cryptography/rsa-oaep")).toBeDefined();
    expect(byRule(f, "source/pycryptodome/keygen-rsa")?.algorithm).toBe("RSA-2048");
    expect(byRule(f, "source/python-hashlib/weak-hash")?.algorithm).toBe("MD5");
    expect(byRule(f, "jwt/pyjwt/rsa")?.location?.line).toBe(11);
    expect(byRule(f, "jwt/pyjwt/ecdsa")?.location?.line).toBe(12);
    expect(byRule(f, "jwt/pyjwt/hmac")?.location?.line).toBe(12);
    expect(f.every((x) => x.confidence === "medium")).toBe(true);
  });

  it("ignores calls in comments but not in strings next to a '#'", () => {
    const f = scanContent("a.py", 'import hashlib\n# hashlib.md5(b"old")\nlabel = "#tag"; h = hashlib.sha1(b"x")');
    const hashes = f.filter((x) => x.ruleId === "source/python-hashlib/weak-hash");
    expect(hashes).toHaveLength(1);
    expect(hashes[0]?.location?.line).toBe(3);
  });

  it("does not attribute cryptography-style calls without the import", () => {
    expect(scanContent("a.py", "rsa.generate_private_key(key_size=2048)")).toEqual([]);
  });
});

describe("Go (regex, comments stripped, import-gated)", () => {
  it("covers crypto/rsa, crypto/ecdsa, crypto/ecdh, crypto/md5", () => {
    const code = [
      "package main",
      'import ("crypto/rsa"; "crypto/ecdsa"; "crypto/ecdh"; "crypto/elliptic"; "crypto/md5")',
      "// rsa.GenerateKey(rand.Reader, 512) in a comment",
      "k, _ := rsa.GenerateKey(rand.Reader, 1024)",
      "e, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)",
      "x, _ := ecdh.X25519().GenerateKey(rand.Reader)",
      "s := md5.Sum(data)",
      "sig, _ := rsa.SignPKCS1v15(nil, k, crypto.SHA1, h)",
    ].join("\n");
    const f = scanContent("cmd/main.go", code);
    const rsa = f.filter((x) => x.ruleId === "source/go/keygen-rsa");
    expect(rsa).toHaveLength(1);
    expect(rsa[0]?.algorithm).toBe("RSA-1024");
    expect(byRule(f, "source/go/keygen-ec")?.algorithm).toBe("ECDSA-P-256");
    expect(byRule(f, "source/go/ecdh")?.algorithm).toBe("X25519");
    expect(byRule(f, "source/go/weak-hash")?.algorithm).toBe("MD5");
    expect(byRule(f, "source/go/rsa-signature")?.severity).toBe("high"); // SHA-1 digest
  });

  it("needs the package import (an unrelated local `rsa` identifier does not fire)", () => {
    expect(scanContent("a.go", "package x\nfunc f() { rsa.GenerateKey(r, 2048) }")).toEqual([]);
  });
});

describe("JVM (regex, comments stripped)", () => {
  it("covers KeyPairGenerator, Signature, KeyAgreement, Cipher and MessageDigest", () => {
    const code = [
      "class App {",
      '  KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");',
      "  { kpg.initialize(1024); }",
      '  Signature s = Signature.getInstance("SHA1withRSA");',
      '  KeyAgreement ka = KeyAgreement.getInstance("ECDH");',
      '  Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");',
      '  MessageDigest md = MessageDigest.getInstance("MD5");',
      '  Cipher d = Cipher.getInstance("DESede/CBC/PKCS5Padding");',
      '  /* KeyPairGenerator.getInstance("DSA") */',
      '  Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");',
      "}",
    ].join("\n");
    const f = scanContent("src/main/java/App.java", code);
    expect(byRule(f, "source/java/keygen-rsa")?.severity).toBe("high"); // initialize(1024)
    expect(byRule(f, "source/java/rsa-signature")?.severity).toBe("high"); // SHA-1
    expect(byRule(f, "source/java/key-agreement")?.algorithm).toBe("ECDH");
    expect(byRule(f, "source/java/rsa-encryption")).toBeDefined();
    expect(byRule(f, "source/java/weak-hash")?.algorithm).toBe("MD5");
    expect(byRule(f, "source/java/weak-cipher")?.algorithm).toBe("DESEDE");
    expect(byRule(f, "source/java/keygen-dsa")).toBeUndefined(); // commented out
    expect(f.some((x) => x.location?.line === 10)).toBe(false); // AES-GCM
  });

  it("applies the same rules to Kotlin", () => {
    const f = scanContent("App.kt", 'val kpg = KeyPairGenerator.getInstance("EC")');
    expect(byRule(f, "source/java/keygen-ec")).toBeDefined();
  });
});
