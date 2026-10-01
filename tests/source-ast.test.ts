import { describe, expect, it } from "vitest";
import { scanContent } from "../src/scanners/source";
import { isJsTsFile } from "../src/scanners/source-ast";

// A well-formed but fake PEM body (>= 40 base64 chars) so PRIVATE_KEY matches.
const PEM_BODY = "MIIBOgIBAAJBAKbogusexamplecontentnotarealkeyAAAAAAAAAAAAAAAAAAAAAA";
const pem = (): string => `-----BEGIN RSA PRIVATE KEY-----\n${PEM_BODY}\n-----END RSA PRIVATE KEY-----`;

describe("isJsTsFile", () => {
  it("recognizes the JS/TS family and nothing else", () => {
    for (const f of ["a.js", "a.mjs", "a.cjs", "a.jsx", "a.ts", "a.tsx", "a.mts", "a.cts"]) {
      expect(isJsTsFile(f), f).toBe(true);
    }
    for (const f of ["a.py", "a.rs", "a.go", "a.md", "a.json"]) {
      expect(isJsTsFile(f), f).toBe(false);
    }
  });
});

describe("AST source scanner", () => {
  it("kills the comment false positive the regex cannot", () => {
    expect(scanContent("x.ts", '// crypto.createHash("md5")')).toEqual([]);
  });

  it("kills the string-literal false positive", () => {
    expect(scanContent("x.ts", `const s = 'crypto.createHash("md5")';`)).toEqual([]);
  });

  it("ignores a locally-shadowed createHash (binding is not node:crypto)", () => {
    expect(scanContent("x.ts", 'const createHash = (a) => a; createHash("md5");')).toEqual([]);
  });

  it("reports an import-resolved weak hash with citations, capped at high confidence (and parses TS)", () => {
    const f = scanContent("x.ts", 'import { createHash } from "node:crypto";\nconst t: string = createHash("sha1").digest("hex");');
    const hash = f.filter((x) => x.category === "source");
    expect(hash).toHaveLength(1);
    expect(hash[0]?.ruleId).toBe("source/node-crypto/weak-hash");
    // Resolving the API proves SHA-1 is called, not that anything depends on
    // its collision resistance, so a weak hash is never `confirmed`.
    expect(hash[0]?.confidence).toBe("high");
    expect(hash[0]?.severity).toBe("medium");
    expect(hash[0]?.algorithm).toBe("SHA-1");
    expect(hash[0]?.references?.length).toBeGreaterThan(0);
  });

  it("resolves a require+destructure cipher binding", () => {
    const f = scanContent("x.ts", 'const { createCipheriv } = require("crypto");\ncreateCipheriv("des-ede3-cbc", k, iv);');
    const cipher = f.find((x) => x.category === "source");
    expect(cipher?.algorithm).toBe("DES-EDE3-CBC");
    expect(cipher?.confidence).toBe("confirmed");
  });

  it("preserves recall for unresolved member calls (parity with the old regex)", () => {
    const f = scanContent("legacy.js", 'crypto.createCipheriv("des-ede3-cbc",k,iv);\njwt.sign(p,k,{algorithm:"none"});');
    const des = f.find((x) => x.category === "source" && /des/i.test(x.title));
    const none = f.find((x) => x.category === "jwt");
    expect(des?.confidence).toBe("high");
    expect(none?.severity).toBe("critical");
  });

  it("flags only the JWT algorithm inside a real sign() options object", () => {
    const f = scanContent("x.ts", 'import jwt from "jsonwebtoken";\nconst other = "ES256";\njwt.sign(p, s, { algorithm: "HS256" });');
    const jwtFindings = f.filter((x) => x.category === "jwt");
    expect(jwtFindings).toHaveLength(1);
    expect(jwtFindings[0]?.title).toContain("HS256");
    expect(jwtFindings[0]?.confidence).toBe("confirmed");
  });

  it("flags every algorithm in a verify() algorithms array", () => {
    const f = scanContent("x.ts", 'import jwt from "jsonwebtoken";\njwt.verify(t, k, { algorithms: ["RS256", "HS256"] });');
    const jwtFindings = f.filter((x) => x.category === "jwt");
    expect(jwtFindings).toHaveLength(2);
    expect(jwtFindings.find((x) => x.title.includes("RS256"))?.severity).toBe("high");
    expect(jwtFindings.find((x) => x.title.includes("HS256"))?.severity).toBe("low");
  });

  it("upgrades a private key inside a string literal to confirmed", () => {
    const f = scanContent("src/secrets.ts", `const KEY = \`${pem()}\`;`);
    const key = f.find((x) => x.category === "keys");
    expect(key?.severity).toBe("critical");
    expect(key?.confidence).toBe("confirmed");
  });

  it("still flags a private key hidden in a comment (cross-cutting regex), at high confidence", () => {
    const f = scanContent("src/secrets.ts", `/*\n${pem()}\n*/\nexport const ok = 1;`);
    const key = f.find((x) => x.category === "keys");
    expect(key?.severity).toBe("critical");
    expect(key?.confidence).toBe("high");
  });

  it("falls back to regex for a raw PEM dumped into a .ts file (parse failure)", () => {
    const f = scanContent("src/secrets.ts", pem());
    const key = f.find((x) => x.category === "keys");
    expect(key?.severity).toBe("critical");
    expect(key?.confidence).toBe("high");
  });

  it("uses the lower-confidence regex rules for non-JS languages", () => {
    const f = scanContent("hash.py", "import hashlib\nhashlib.md5(data)");
    const hash = f.find((x) => x.category === "source");
    expect(hash?.ruleId).toBe("source/python-hashlib/weak-hash");
    expect(hash?.confidence).toBe("medium");
  });
});

describe("AST recall on common call forms", () => {
  const cipher = (file: string, code: string) =>
    scanContent(file, code).find((x) => x.ruleId === "source/node-crypto/weak-cipher");

  it("resolves an aliased named import", () => {
    const f = cipher("a.ts", 'import { createCipheriv as enc } from "node:crypto";\nenc("des-ede3-cbc", k, iv);');
    expect(f?.confidence).toBe("confirmed");
  });

  it("resolves destructuring from a required namespace, with a renamed binding", () => {
    const f = cipher("a.js", 'const c = require("crypto");\nconst { createCipheriv: mk } = c;\nmk("rc4", k, null);');
    expect(f?.confidence).toBe("confirmed");
    expect(f?.algorithm).toBe("RC4");
  });

  it("resolves a const alias of a module method", () => {
    const f = scanContent("a.js", 'const c = require("crypto");\nconst gen = c.generateKeyPairSync;\ngen("rsa", { modulusLength: 2048 });');
    const keygen = f.find((x) => x.ruleId === "source/node-crypto/keygen-rsa");
    expect(keygen?.confidence).toBe("confirmed");
    expect(keygen?.algorithm).toBe("RSA-2048");
  });

  it("resolves an inline require() receiver (the regex fallback used to be the only path that saw it)", () => {
    const f = scanContent("a.js", 'require("crypto").createHash("md5").update(x);');
    expect(f.find((x) => x.ruleId === "source/node-crypto/weak-hash")?.algorithm).toBe("MD5");
  });

  it("resolves optional chaining", () => {
    const f = scanContent("a.ts", 'import * as crypto from "crypto";\ncrypto?.createECDH?.("prime256v1");');
    const ecdh = f.find((x) => x.ruleId === "source/node-crypto/ecdh");
    expect(ecdh?.confidence).toBe("confirmed");
    expect(ecdh?.algorithm).toBe("ECDH-P-256");
  });

  it("resolves a global member chain to WebCrypto", () => {
    const f = scanContent("a.js", 'globalThis.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign"]);');
    const key = f.find((x) => x.ruleId === "source/webcrypto/keygen-ec");
    expect(key?.confidence).toBe("confirmed");
    expect(key?.algorithm).toBe("ECDSA-P-384");
  });

  it("sees through TypeScript assertions and the (0, fn)() shape transpilers emit", () => {
    const f = scanContent(
      "a.ts",
      'import crypto from "crypto";\n(crypto as any).createCipheriv("des", k, iv);\ncrypto!.createSign("RSA-SHA1");\n(0, crypto.publicEncrypt)(pub, buf);',
    );
    expect(f.find((x) => x.ruleId === "source/node-crypto/weak-cipher")?.confidence).toBe("confirmed");
    expect(f.find((x) => x.ruleId === "source/node-crypto/signature")?.severity).toBe("high"); // SHA-1 signature
    expect(f.find((x) => x.ruleId === "source/node-crypto/rsa-encryption")?.confidence).toBe("confirmed");
  });

  it("resolves an interop-wrapped require from transpiled CommonJS", () => {
    const f = cipher("a.js", 'var _crypto = _interopRequireDefault(require("crypto"));\n(0, _crypto.default.createCipheriv)("des-ede3-cbc", k, iv);');
    expect(f).toBeDefined();
    expect(f?.confidence).toBe("high"); // a `var` binding can be reassigned
  });

  it("resolves a destructured dynamic import", () => {
    const f = scanContent(
      "a.mjs",
      'const { webcrypto } = await import("node:crypto");\nawait webcrypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, key, data);',
    );
    expect(f.find((x) => x.ruleId === "source/webcrypto/rsa-signature")?.confidence).toBe("confirmed");
  });

  it("resolves const string and options bindings used as arguments", () => {
    const hash = cipher("a.ts", 'import { createCipheriv } from "crypto";\nconst ALG = "des-ede3-cbc";\ncreateCipheriv(ALG, k, iv);');
    expect(hash?.algorithm).toBe("DES-EDE3-CBC");
    const jwtF = scanContent("b.ts", 'import jwt from "jsonwebtoken";\nconst opts = { algorithm: "RS256" };\njwt.sign(p, k, opts);');
    expect(jwtF.find((x) => x.ruleId === "jwt/jsonwebtoken/rsa")?.confidence).toBe("confirmed");
  });
});

describe("AST scope analysis (shadowing)", () => {
  it("does not confirm a call whose receiver is a parameter shadowing the import", () => {
    // The CHANGELOG claimed shadowed names no longer fire; the old binding table
    // was file-wide, so this was reported as confirmed.
    const f = scanContent(
      "x.ts",
      'import crypto from "node:crypto";\nexport function f(crypto) { return crypto.createCipheriv("des", k, iv); }',
    );
    const hit = f.find((x) => x.ruleId === "source/node-crypto/weak-cipher");
    expect(hit).toBeDefined(); // the method name is still a strong signal
    expect(hit?.confidence).toBe("high");
  });

  it("drops a direct call whose name is re-declared locally after the import", () => {
    const f = scanContent(
      "x.ts",
      'import { createCipheriv } from "crypto";\nfunction g() { const createCipheriv = (a) => a; return createCipheriv("des"); }',
    );
    expect(f.filter((x) => x.category === "source")).toEqual([]);
  });

  it("still confirms the import outside the shadowing scope", () => {
    const f = scanContent(
      "x.ts",
      'import { createCipheriv } from "crypto";\nfunction g() { const createCipheriv = (a) => a; return createCipheriv("des"); }\ncreateCipheriv("rc4", k, null);',
    );
    const hits = f.filter((x) => x.ruleId === "source/node-crypto/weak-cipher");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.algorithm).toBe("RC4");
    expect(hits[0]?.confidence).toBe("confirmed");
  });

  it("scopes block and catch bindings", () => {
    const f = scanContent(
      "x.ts",
      [
        'import jwt from "jsonwebtoken";',
        '{ const jwt = makeFake(); jwt.sign(p, k, { algorithm: "RS256" }); }',
        'try { run(); } catch (jwt) { jwt.sign(p, k, { algorithm: "ES256" }); }',
        'jwt.sign(p, k, { algorithm: "HS256" });',
      ].join("\n"),
    );
    const byAlg = (alg: string) => f.find((x) => x.algorithm === `JWT-${alg}`);
    expect(byAlg("RS256")?.confidence).toBe("high");
    expect(byAlg("ES256")?.confidence).toBe("high");
    expect(byAlg("HS256")?.confidence).toBe("confirmed");
  });

  it("treats a let-bound module as high, not confirmed (it can be reassigned)", () => {
    const f = scanContent("x.js", 'let c = require("crypto");\nc.createCipheriv("des", k, iv);');
    expect(f.find((x) => x.ruleId === "source/node-crypto/weak-cipher")?.confidence).toBe("high");
  });

  it("hoists var declarations to the function scope", () => {
    const f = scanContent("x.js", 'function f() { if (x) { var c = require("crypto"); } return c.createCipheriv("des", k, iv); }');
    expect(f.find((x) => x.ruleId === "source/node-crypto/weak-cipher")).toBeDefined();
  });

  it("falls back to the regex sweep instead of crashing on a pathologically deep tree", () => {
    const deep = `const x = ${"[".repeat(20_000)}${"]".repeat(20_000)};\ncreateCipheriv("des", k, iv);`;
    const f = scanContent("deep.js", deep);
    expect(f.find((x) => x.ruleId === "source/node-crypto/weak-cipher")?.confidence).toBe("medium");
  });
});
