/**
 * Every algorithm label a scanner can emit is known to the shared vocabulary
 * (src/algorithms.ts) that the CBOM and the risk engine both read.
 *
 * The labels are collected by running the scanners themselves (every regex
 * matcher's own sample, AST call shapes, parsed PEM keys of every type the
 * runtime can generate, the TLS analysis over every key type, signature name
 * and key exchange) plus the JOSE and registry vocabularies, so a scanner that
 * starts emitting a new spelling fails here. That is how `rsassaPss-sha256`
 * shipped as CycloneDX primitive "unknown" with no NIST level.
 */
import { generateKeyPairSync, X509Certificate } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { algorithmUsage, describeAlgorithm } from "../src/algorithms";
import { signatureAlgorithmNames } from "../src/asn1";
import { cnsa2Standing, toKeyType } from "../src/crypto";
import type { KeyType } from "../src/crypto";
import { toCbom } from "../src/output/cbom";
import { buildReport } from "../src/report";
import type { Finding } from "../src/report";
import { REGISTRY } from "../src/scanners/deps/registry";
import { scanContent } from "../src/scanners/source";
import { JWT_ALGORITHM, REGEX_MATCHERS } from "../src/scanners/source-rules";
import { analyzeTls, parseCertificate } from "../src/scanners/tls";
import type { CertInfo, TlsScanResult } from "../src/scanners/tls";

const NOW = new Date("2026-10-01T00:00:00.000Z");

const FILE_FOR = { javascript: "src/a.js", python: "src/a.py", go: "src/a.go", java: "src/A.java" } as const;

/** AST call shapes whose labels the regex samples do not produce. */
const JS_SNIPPETS = [
  'c.generateKeyPairSync("rsa", { modulusLength: 2048 }); c.generateKeyPairSync("rsa"); c.generateKeyPairSync("rsa-pss", { modulusLength: 3072 });',
  'c.generateKeyPairSync("dsa", { modulusLength: 2048 }); c.generateKeyPairSync("dsa");',
  'c.generateKeyPairSync("ec", { namedCurve: "P-256" }); c.generateKeyPairSync("ec", { namedCurve: "prime192v1" }); c.generateKeyPairSync("ec");',
  'c.generateKeyPairSync("ed25519"); c.generateKeyPairSync("ed448"); c.generateKeyPairSync("x25519"); c.generateKeyPairSync("x448");',
  'c.generateKeyPairSync("dh", { group: "modp14" }); c.generateKeyPairSync("dh");',
  'c.createSign("RSA-SHA256"); c.createSign("ecdsa-with-SHA256"); c.createSign("DSA-SHA1"); c.createSign(alg); c.sign("sha256", d, k);',
  'c.createECDH("secp384r1"); c.createECDH(curve); c.createDiffieHellman(2048); c.createDiffieHellman(p); c.getDiffieHellman("modp2");',
  'c.publicEncrypt(k, b); c.privateEncrypt(k, b); c.diffieHellman({ privateKey, publicKey });',
  'c.createHash("md5"); c.createHash("sha1"); c.createCipheriv("des-ede3-cbc", k, iv); c.createCipheriv("rc4", k, iv); c.createCipheriv("rc2-cbc", k, iv); c.createCipheriv("des-ecb", k, iv); c.createCipheriv("desx-cbc", k, iv);',
  'c.createHmac("md5", k); c.createHmac("sha1", k); c.hkdfSync("sha1", a, b, d, 32); c.pbkdf2Sync(p, s, 1, 32, "md5"); c.pbkdf2Sync(p, s, 1, 32, "sha1");',
  'crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 4096 }, true, ["encrypt"]); crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign"]);',
  'crypto.subtle.generateKey({ name: "ECDH" }, true, ["deriveBits"]); crypto.subtle.importKey("raw", b, "Ed448", true, ["verify"]); crypto.subtle.generateKey("X448", true, ["deriveBits"]);',
  'crypto.subtle.sign("RSA-PSS", k, d); crypto.subtle.sign("ECDSA", k, d); crypto.subtle.verify("Ed448", k, s, d); crypto.subtle.deriveBits({ name: "ECDH" }, k, 256); crypto.subtle.deriveBits({ name: "X448" }, k, 256); crypto.subtle.encrypt({ name: "RSA-OAEP" }, k, d);',
].map((code) => `const c = require("crypto");\n${code}`);

/** Regex-language variants beyond each matcher's own sample. */
const OTHER_SNIPPETS: ReadonlyArray<readonly [string, string]> = [
  ["src/a.py", "from Crypto.PublicKey import RSA, DSA, ECC\nRSA.generate()\nDSA.generate()\nECC.generate(curve='P-384')\nECC.generate()"],
  ["src/a.py", "from Crypto.Cipher import DES, ARC4, ARC2\nfrom Crypto.Hash import SHA\nDES.new(k)\nARC4.new(k)\nARC2.new(k)\nSHA.new(d)"],
  ["src/a.py", "from cryptography.hazmat.primitives.asymmetric import ec, x448, ed448\nec.generate_private_key()\nX448PrivateKey.generate()\nEd448PrivateKey.generate()"],
  ["src/a.go", 'import "crypto/ecdsa"\necdsa.GenerateKey(r, rand.Reader)'],
  ["src/a.go", 'import "crypto/ecdh"\necdh.P384()'],
  ["src/a.go", 'import "crypto/des"\ndes.NewCipher(k)'],
  ["src/a.go", 'import "crypto/rsa"\nrsa.GenerateKey(rand.Reader, bits)'],
  ["src/A.java", 'KeyPairGenerator.getInstance("RSASSA-PSS");\nKeyPairGenerator.getInstance("DSA");\nKeyPairGenerator.getInstance("DH");\nKeyPairGenerator.getInstance("Ed448");\nKeyPairGenerator.getInstance("X448");'],
  ["src/A.java", 'KeyAgreement.getInstance("DH");\nKeyAgreement.getInstance("X448");\nSignature.getInstance("Ed448");\nSignature.getInstance("SHA256withDSA");'],
  ["src/A.java", 'Cipher.getInstance("DESede/CBC/PKCS5Padding");\nCipher.getInstance("TripleDES");\nCipher.getInstance("DES");\nCipher.getInstance("RC2");\nCipher.getInstance("ARCFOUR");\nMessageDigest.getInstance("MD2");\nMessageDigest.getInstance("SHA");'],
];

/** Public keys of every type this runtime can generate, as PEM, for the key-block parser. */
function pemPublicKeys(): string[] {
  const shapes: Array<[string, Record<string, unknown>]> = [
    ["rsa", { modulusLength: 1024 }],
    ["rsa-pss", { modulusLength: 2048 }],
    ["dsa", { modulusLength: 2048, divisorLength: 224 }],
    ["ec", { namedCurve: "P-256" }],
    ["ec", { namedCurve: "secp256k1" }],
    ["ec", { namedCurve: "P-521" }],
    ["ed25519", {}],
    ["ed448", {}],
    ["x25519", {}],
    ["x448", {}],
    ["dh", { group: "modp14" }],
    ["ml-dsa-44", {}],
    ["ml-dsa-87", {}],
    ["ml-kem-768", {}],
    ["slh-dsa-sha2-128s", {}],
    ["slh-dsa-shake-256f", {}],
  ];
  const pems: string[] = [];
  for (const [type, options] of shapes) {
    let publicKey: KeyObject;
    try {
      ({ publicKey } = (generateKeyPairSync as unknown as (t: string, o: Record<string, unknown>) => { publicKey: KeyObject })(type, options));
    } catch {
      continue; // a key type this runtime's OpenSSL does not implement
    }
    pems.push(String(publicKey.export({ type: "spki", format: "pem" })));
  }
  return pems;
}

const LEAF: CertInfo = {
  subject: "vocab.example",
  issuer: "Example CA",
  isLeaf: true,
  selfSigned: false,
  keyType: "rsa",
  keyBits: 2048,
  curve: null,
  signatureAlgorithm: "sha256WithRSAEncryption",
  signatureOid: "1.2.840.113549.1.1.11",
  validFrom: "2025-01-01T00:00:00.000Z",
  validTo: "2099-01-01T00:00:00.000Z",
};

const KEY_TYPES: readonly KeyType[] = [
  "rsa",
  "rsa-pss",
  "dsa",
  "ec",
  "ed25519",
  "ed448",
  "ml-kem-512",
  "ml-kem-1024",
  "ml-dsa-44",
  "ml-dsa-65",
  "slh-dsa-sha2-192f",
  "slh-dsa-shake-128s",
  "hss-lms",
  "xmss",
  "xmssmt",
];

/** The RSASSA-PSS digests tls.ts names (`rsassaPss-<digest>`), from the RFC 4055 / NIST digest OIDs. */
const PSS_DIGESTS = ["sha1", "sha224", "sha256", "sha384", "sha512", "sha512-224", "sha512-256", "sha3-224", "sha3-256", "sha3-384", "sha3-512"];

const CERTS = fileURLToPath(new URL("./fixtures/tls-certs/", import.meta.url));

function tls(result: Partial<TlsScanResult>): Finding[] {
  return analyzeTls({ protocol: "TLSv1.3", cipherName: "TLS_AES_256_GCM_SHA384", groupName: "X25519", chain: [LEAF], ...result }, "vocab.example:443", NOW);
}

function tlsLabels(): string[] {
  const findings: Finding[] = [];
  for (const keyType of KEY_TYPES) {
    findings.push(...tls({ chain: [{ ...LEAF, keyType, keyBits: keyType === "rsa" || keyType === "dsa" ? 3072 : null, curve: keyType === "ec" ? "P-384" : null }] }));
  }
  findings.push(...tls({ chain: [{ ...LEAF, keyType: "ec", keyBits: null, curve: "prime192v1" }] }));
  for (const signatureAlgorithm of [...signatureAlgorithmNames(), ...PSS_DIGESTS.map((d) => `rsassaPss-${d}`)]) {
    findings.push(...tls({ chain: [{ ...LEAF, signatureAlgorithm }, { ...LEAF, isLeaf: false, subject: "Intermediate", signatureAlgorithm }] }));
  }
  for (const name of ["pss-sha1-default.pem", "pss-sha256.pem"]) {
    const parsed = parseCertificate(new X509Certificate(readFileSync(`${CERTS}${name}`)).raw, true);
    if (parsed) findings.push(...tls({ chain: [parsed] }));
  }
  // Key exchange: TLS 1.2 static RSA, DHE with and without a size, ECDHE with and without a group, TLS 1.3 groups.
  findings.push(...tls({ protocol: "TLSv1.2", cipherName: "AES256-GCM-SHA384", groupName: null }));
  findings.push(...tls({ protocol: "TLSv1.2", cipherName: "DHE-RSA-AES128-GCM-SHA256", groupName: null, groupBits: 1024 }));
  findings.push(...tls({ protocol: "TLSv1.2", cipherName: "DHE-RSA-AES128-GCM-SHA256", groupName: null }));
  findings.push(...tls({ protocol: "TLSv1.2", cipherName: "ECDHE-RSA-AES128-GCM-SHA256", groupName: null }));
  for (const groupName of ["X25519", "X448", "prime256v1", "secp384r1", "secp521r1", "brainpoolP256r1"]) {
    findings.push(...tls({ protocol: "TLSv1.2", cipherName: "ECDHE-ECDSA-AES256-GCM-SHA384", groupName }));
    findings.push(...tls({ groupName }));
  }
  findings.push(...tls({ groupName: null, groupBits: 2048 }));
  for (const groupName of ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "MLKEM768", "MLKEM1024", "X25519Kyber768Draft00"]) {
    findings.push(...tls({ groupName }));
  }
  return findings.flatMap((f) => [f.algorithm, ...(f.certificates ?? []).flatMap((c) => [c.publicKey, c.signatureAlgorithm])]).filter((l): l is string => !!l);
}

function sourceLabels(): string[] {
  const findings: Finding[] = [];
  for (const matcher of REGEX_MATCHERS) findings.push(...scanContent(FILE_FOR[matcher.language], matcher.sample));
  for (const code of JS_SNIPPETS) findings.push(...scanContent("src/a.js", code));
  for (const [path, code] of OTHER_SNIPPETS) findings.push(...scanContent(path, code));
  for (const pem of pemPublicKeys()) findings.push(...scanContent("keys/k.pem", pem));
  return findings.map((f) => f.algorithm).filter((l): l is string => !!l);
}

/** Every alternative of the JWT algorithm pattern the source scanner accepts. */
function joseLabels(): string[] {
  const candidates = [
    "none",
    ...["HS", "RS", "PS", "ES"].flatMap((p) => ["256", "384", "512"].map((n) => `${p}${n}`)),
    "ES256K",
    "EdDSA",
    "Ed25519",
    "Ed448",
    "RSA1_5",
    "RSA-OAEP",
    "RSA-OAEP-256",
    "RSA-OAEP-384",
    "RSA-OAEP-512",
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW",
  ];
  for (const alg of candidates) expect(JWT_ALGORITHM.test(alg), alg).toBe(true);
  return candidates.map((alg) => `JWT-${alg}`);
}

/** Labels that honestly mean "not recognized": an unreadable key and an unknown signature OID. */
const HONEST_UNKNOWNS: ReadonlySet<string> = new Set(["unknown-key", "unknown"]);
/** Keys whose use the label leaves open, assessed under both threat models. */
const DUAL_USE = /^(?:rsa(?:-\d+|-\?)?|ec)$/i;
const PUBLIC_KEY_PRIMITIVES = new Set(["signature", "kem", "key-agree", "pke"]);

describe("the algorithm vocabulary", () => {
  const labels = [...new Set([...sourceLabels(), ...tlsLabels(), ...joseLabels(), ...REGISTRY.flatMap((e) => e.algorithms)])].sort();

  it("collects the scanners' labels", () => {
    expect(labels.length).toBeGreaterThan(120);
    for (const expected of ["rsassaPss-sha1", "rsassaPss-sha256", "DHE-1024", "FFDHE-2048", "static-RSA-key-exchange", "ECDHE-X25519", "PBKDF2-SHA-1", "HMAC-MD5", "DES3", "ARC2", "RSA/DSA/ECDSA", "ECDSA/DSA", "EC", "HSS-LMS"]) {
      expect(labels, expected).toContain(expected);
    }
  });

  it("types every label with a CycloneDX primitive", () => {
    const unknown = labels.filter((label) => !HONEST_UNKNOWNS.has(label) && describeAlgorithm(label).primitive === "unknown");
    expect(unknown).toEqual([]);
  });

  it("gives the risk engine a use for every label except open-ended keys", () => {
    const missing = labels.filter((label) => {
      if (HONEST_UNKNOWNS.has(label) || DUAL_USE.test(label) || describeAlgorithm(label).primitive === "other") return false;
      return algorithmUsage(label).length === 0;
    });
    expect(missing).toEqual([]);
  });

  it("has a CNSA 2.0 standing for every public-key label and none for symmetric ones", () => {
    const disagreements = labels.filter((label) => {
      if (HONEST_UNKNOWNS.has(label)) return false;
      const publicKey = PUBLIC_KEY_PRIMITIVES.has(describeAlgorithm(label).primitive);
      return publicKey !== (cnsa2Standing(label) !== null);
    });
    expect(disagreements).toEqual([]);
  });

  it("states the NIST level wherever the label determines it", () => {
    expect(describeAlgorithm("rsassaPss-sha256")).toEqual({ primitive: "signature", nistQuantumSecurityLevel: 0, oid: "1.2.840.113549.1.1.10" });
    expect(describeAlgorithm("DHE-1024")).toMatchObject({ primitive: "key-agree", nistQuantumSecurityLevel: 0, parameterSetIdentifier: "1024", classicalSecurityLevel: 80 });
    expect(describeAlgorithm("FFDHE-2048")).toMatchObject({ primitive: "key-agree", nistQuantumSecurityLevel: 0, classicalSecurityLevel: 112 });
    expect(describeAlgorithm("static-RSA-key-exchange")).toMatchObject({ primitive: "pke", nistQuantumSecurityLevel: 0 });
    expect(describeAlgorithm("ECDSA-prime192v1")).toMatchObject({ curve: "secp192r1", classicalSecurityLevel: 80 });
    expect(describeAlgorithm("JWT-ES256K")).toMatchObject({ primitive: "signature", curve: "secp256k1" });
    expect(describeAlgorithm("JWT-RSA-OAEP-256")).toMatchObject({ primitive: "pke", oid: "1.2.840.113549.1.1.7" });
    expect(describeAlgorithm("JWT-ECDH-ES+A256KW").primitive).toBe("key-agree");
    expect(describeAlgorithm("HashML-DSA-87-with-SHA512")).toMatchObject({ nistQuantumSecurityLevel: 5, oid: "2.16.840.1.101.3.4.3.34" });
    expect(describeAlgorithm("PBKDF2-SHA-1")).toEqual({ primitive: "kdf", oid: "1.2.840.113549.1.5.12" });
    expect(describeAlgorithm("EC", ["key-establishment"]).primitive).toBe("key-agree");
    expect(describeAlgorithm("RSA-2048", ["encryption", "authentication"]).primitive).toBe("pke");
  });
});

describe("the CBOM for a TLS 1.2 static-RSA server with an RSASSA-PSS certificate", () => {
  const leaf = parseCertificate(new X509Certificate(readFileSync(`${CERTS}pss-sha256.pem`)).raw, true);
  if (!leaf) throw new Error("pss-sha256.pem did not parse");
  const findings = analyzeTls(
    { protocol: "TLSv1.2", cipherName: "AES256-GCM-SHA384", groupName: null, chain: [leaf] },
    "pss.example:443",
    NOW,
    { host: "pss.example", port: 443 },
  );
  const cbom = JSON.parse(toCbom(buildReport("pss.example", findings, NOW))) as {
    components: Array<{ name: string; cryptoProperties?: { assetType: string; oid?: string; algorithmProperties?: { primitive: string; nistQuantumSecurityLevel?: number } } }>;
  };
  const algorithm = (name: string) => cbom.components.find((c) => c.cryptoProperties?.assetType === "algorithm" && c.name === name);

  it("types the PSS signature, the key transport and the leaf key", () => {
    expect(algorithm("rsassaPss-sha256")?.cryptoProperties).toMatchObject({
      oid: "1.2.840.113549.1.1.10",
      algorithmProperties: { primitive: "signature", nistQuantumSecurityLevel: 0 },
    });
    expect(algorithm("static-RSA-key-exchange")?.cryptoProperties?.algorithmProperties?.primitive).toBe("pke");
    // The leaf key decrypts the premaster secret, so it is public-key encryption here, not a signature key.
    expect(algorithm(`RSA-${leaf.keyBits ?? 0}`)?.cryptoProperties?.algorithmProperties?.primitive).toBe("pke");
    expect(cbom.components.filter((c) => c.cryptoProperties?.algorithmProperties?.primitive === "unknown")).toEqual([]);
  });

  it("names the key type it parsed", () => {
    expect(toKeyType("rsa-pss")).toBe("rsa-pss");
  });
});
