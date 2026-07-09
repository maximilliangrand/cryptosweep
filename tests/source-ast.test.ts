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

  it("reports an import-resolved weak hash at confirmed confidence with citations (and parses TS)", () => {
    const f = scanContent("x.ts", 'import { createHash } from "node:crypto";\nconst t: string = createHash("sha1").digest("hex");');
    const hash = f.filter((x) => x.category === "source");
    expect(hash).toHaveLength(1);
    expect(hash[0]?.confidence).toBe("confirmed");
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

  it("falls back to regex for non-JS languages", () => {
    const f = scanContent("hash.py", 'import hashlib\ncrypto.createHash("md5")');
    const hash = f.find((x) => x.category === "source");
    expect(hash?.confidence).toBe("medium");
  });
});
