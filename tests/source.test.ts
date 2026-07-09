import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { scanContent, scanSource } from "../src/scanners/source";

// Dummy PEM markers only — not a real key. Built at runtime into a temp dir.
const FAKE_RSA_KEY = [
  "-----BEGIN RSA PRIVATE KEY-----",
  "MIIBOgIBAAJBAKboguscontentnotarealkeyAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "-----END RSA PRIVATE KEY-----",
].join("\n");

const AUTH_SOURCE = `
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

export function fingerprint(input) {
  return crypto.createHash("md5").update(input).digest("hex");
}

export function issue(payload, secret) {
  return jwt.sign(payload, secret, { algorithm: "HS256" });
}
`;

describe("scanSource (fixture directory)", () => {
  let root: string;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), "csw-src-test-"));
    await writeFile(join(root, "auth.js"), AUTH_SOURCE, "utf8");
    await writeFile(join(root, "id_rsa.pem"), FAKE_RSA_KEY, "utf8");
    // Ignored directory — must not contribute findings.
    await mkdir(join(root, "node_modules", "evil"), { recursive: true });
    await writeFile(
      join(root, "node_modules", "evil", "index.js"),
      'require("crypto").createHash("md5");',
      "utf8",
    );
  });

  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("finds the MD5 hash, the HS256 JWT, and the hardcoded RSA key", async () => {
    const findings = await scanSource(root);

    const md5 = findings.filter((f) => f.category === "source" && /md5/i.test(f.title));
    const jwt = findings.filter((f) => f.category === "jwt" && f.title.includes("HS256"));
    const keys = findings.filter((f) => f.category === "keys" && /private key/i.test(f.title));

    expect(md5).toHaveLength(1);
    expect(jwt).toHaveLength(1);
    expect(keys).toHaveLength(1);

    // Hardcoded private key is the most severe finding.
    expect(keys[0]?.severity).toBe("critical");
    // Evidence is file:line.
    expect(md5[0]?.evidence).toMatch(/auth\.js:\d+/);
  });

  it("skips ignored directories like node_modules", async () => {
    const findings = await scanSource(root);
    expect(findings.every((f) => !f.evidence.includes("node_modules"))).toBe(true);
  });

  it("emits an explicit truncation finding when the file budget is exhausted", async () => {
    const findings = await scanSource(root, { maxFiles: 1 });
    const truncated = findings.find((f) => f.title.includes("resource limit"));
    expect(truncated).toBeDefined();
    expect(truncated?.severity).toBe("info");
  });
});

describe("scanContent (unit)", () => {
  it("returns no findings for modern crypto without JWTs", () => {
    const clean = 'crypto.createHash("sha256").update(x).digest("hex");\nconst aes = "aes-256-gcm";';
    expect(scanContent("clean.ts", clean)).toEqual([]);
  });

  it("does not flag JWT algorithm strings outside jsonwebtoken usage", () => {
    // "ES256" appears but no jsonwebtoken import/usage in the file.
    const unrelated = 'const label = "ES256 reference doc";';
    expect(scanContent("doc.ts", unrelated)).toEqual([]);
  });

  it("flags a weak DES cipher and rates alg:none as critical", () => {
    const content = [
      'crypto.createCipheriv("des-ede3-cbc", key, iv);',
      'jwt.sign(p, k, { algorithm: "none" });',
    ].join("\n");
    const findings = scanContent("legacy.js", content);
    expect(findings.some((f) => f.category === "source" && /des/i.test(f.title))).toBe(true);
    expect(findings.some((f) => f.category === "jwt" && f.severity === "critical")).toBe(true);
  });
});

describe("scanContent (false-positive calibration)", () => {
  it("does not flag an elided PEM block in a README as a private key", () => {
    const readme = [
      "## Example",
      "```",
      "-----BEGIN PRIVATE KEY-----",
      "...your key here...",
      "-----END PRIVATE KEY-----",
      "```",
    ].join("\n");
    const findings = scanContent("README.md", readme);
    expect(findings.filter((f) => f.category === "keys")).toHaveLength(0);
  });

  it("de-rates a real-looking key shown in documentation instead of crying critical", () => {
    const doc = [
      "Here is a sample key:",
      "-----BEGIN PRIVATE KEY-----",
      "MIIBOgIBAAJBAKbogusexamplecontentnotarealkeyAAAAAAAAAAAAAAAAAAAAAA",
      "-----END PRIVATE KEY-----",
    ].join("\n");
    const findings = scanContent("docs/setup.md", doc);
    const key = findings.find((f) => f.category === "keys");
    expect(key).toBeDefined();
    expect(key?.severity).not.toBe("critical");
    expect(key?.confidence).toBe("low");
  });

  it("de-rates a JWT alg:none appearing in a test file", () => {
    const spec = 'const jwt = require("jsonwebtoken");\njwt.sign(p, k, { algorithm: "none" });';
    const findings = scanContent("auth.test.js", spec);
    const none = findings.find((f) => f.category === "jwt");
    expect(none).toBeDefined();
    expect(none?.severity).not.toBe("critical");
    expect(none?.confidence).toBe("low");
  });

  it("keeps full confidence and critical severity for a real key in source", () => {
    const src = [
      "-----BEGIN RSA PRIVATE KEY-----",
      "MIIBOgIBAAJBAKbogusexamplecontentnotarealkeyAAAAAAAAAAAAAAAAAAAAAA",
      "-----END RSA PRIVATE KEY-----",
    ].join("\n");
    const findings = scanContent("src/secrets.ts", src);
    const key = findings.find((f) => f.category === "keys");
    expect(key?.severity).toBe("critical");
    expect(key?.confidence).toBe("high");
  });
});
