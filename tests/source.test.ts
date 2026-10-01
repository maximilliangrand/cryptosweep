import { chmod, mkdtemp, mkdir, open, rm, writeFile } from "node:fs/promises";
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
    expect(findings.every((f) => !f.location?.path?.includes("node_modules"))).toBe(true);
    // The skip itself is recorded, so the inventory says what it left out.
    expect(findings.find((f) => f.ruleId === "source/directories-skipped")?.evidence).toBe("node_modules");
  });

  it("emits an explicit truncation finding when the file budget is exhausted", async () => {
    const findings = await scanSource(root, { maxFiles: 1 });
    const truncated = findings.find((f) => f.title.includes("resource limit"));
    expect(truncated).toBeDefined();
    expect(truncated?.severity).toBe("info");
  });
});

describe("scanSource (resilience)", () => {
  let root: string;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), "csw-src-resilience-"));
    await writeFile(join(root, "auth.js"), AUTH_SOURCE, "utf8");
    await writeFile(join(root, "id_rsa.pem"), FAKE_RSA_KEY, "utf8");
    await writeFile(join(root, "locked.txt"), "unreadable", "utf8");
    await chmod(join(root, "locked.txt"), 0o000);
  });

  afterAll(async () => {
    await chmod(join(root, "locked.txt"), 0o600).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  });

  it("keeps scanning past an unreadable file and reports the coverage gap", async () => {
    const findings = await scanSource(root);
    // The whole scan used to abort on the first EACCES, discarding every
    // finding already collected.
    expect(findings.some((f) => f.category === "source" && /md5/i.test(f.title))).toBe(true);
    expect(findings.some((f) => f.category === "keys")).toBe(true);
    const skipped = findings.find((f) => f.ruleId === "source/unreadable-path");
    expect(skipped?.severity).toBe("info");
    expect(skipped?.evidence).toContain("locked.txt");
  });

  it("skips a file above the cap on its stat size, never reading it into memory", async () => {
    const huge = join(root, "huge.bin");
    const handle = await open(huge, "w");
    await handle.truncate(2_500_000_001); // sparse, occupies no blocks
    await handle.close();
    try {
      // Node's readFile hard-fails above 2 GiB (ERR_FS_FILE_TOO_LARGE). The walk
      // used to read first and compare sizes second, so one big file aborted the
      // scan — the opposite of the memory ceiling it claims to enforce.
      const findings = await scanSource(root);
      expect(findings.some((f) => f.category === "source" && /md5/i.test(f.title))).toBe(true);
    } finally {
      await rm(huge, { force: true });
    }
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

  it("flags a passphrase-encrypted PEM key carrying RFC 1421 headers", () => {
    // `ssh-keygen` with a passphrase and `openssl genrsa -aes256` both emit
    // this form, and it is committed precisely because the passphrase feels
    // like protection. The header lines broke the old base64-only body match.
    const encrypted = [
      "-----BEGIN RSA PRIVATE KEY-----",
      "Proc-Type: 4,ENCRYPTED",
      "DEK-Info: AES-256-CBC,0123456789ABCDEF0123456789ABCDEF",
      "",
      "MIIBOgIBAAJBAKbogusexamplecontentnotarealkeyAAAAAAAAAAAAAAAAAAAAAA",
      "-----END RSA PRIVATE KEY-----",
    ].join("\n");
    const findings = scanContent("src/deploy_key.pem", encrypted);
    const key = findings.find((f) => f.category === "keys");
    expect(key?.severity).toBe("critical");
    expect(key?.title).toMatch(/private key/i);
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
