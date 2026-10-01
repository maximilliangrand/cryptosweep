import { generateKeyPairSync } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { mkdir, mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scanContent, scanSource } from "../src/scanners/source";

const PEM_BODY = "MIIBOgIBAAJBAKbogusexamplecontentnotarealkeyAAAAAAAAAAAAAAAAAAAAAA";
const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----\n${PEM_BODY}\n-----END RSA PRIVATE KEY-----\n`;

let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "csw-walk-"));
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

describe("coverage gaps are explicit", () => {
  it("reports files over the size cap and binary-looking files instead of a silent clean result", async () => {
    // Audit repro: a 2.1 MB bundle and a binary, each holding a private key, gave 'Findings: 0'.
    await writeFile(join(root, "bundle.min.js"), PRIVATE_KEY + "x".repeat(2_100_000));
    await writeFile(join(root, "pad.bin"), Buffer.concat([Buffer.from([0]), Buffer.from(PRIVATE_KEY)]));
    const findings = await scanSource(root);
    const tooLarge = findings.find((f) => f.ruleId === "source/file-too-large");
    const binary = findings.find((f) => f.ruleId === "source/binary-skipped");
    expect(tooLarge?.evidence).toBe("bundle.min.js");
    expect(tooLarge?.severity).toBe("info");
    expect(binary?.evidence).toBe("pad.bin");
    // An unread JS bundle is also an AST gap, which keeps reconcile from trusting partial evidence.
    expect(findings.find((f) => f.ruleId === "source/ast-fallback")?.evidence).toBe("bundle.min.js");
    expect(findings.every((f) => typeof f.ruleId === "string")).toBe(true);
  });

  it("reports a JS/TS file that fell back to the regex sweep", async () => {
    await writeFile(join(root, "broken.js"), 'const x = ;\ncrypto.createHash("md5");\n');
    const findings = await scanSource(root);
    expect(findings.find((f) => f.ruleId === "source/ast-fallback")?.evidence).toBe("broken.js");
    expect(findings.find((f) => f.ruleId === "source/node-crypto/weak-hash")?.confidence).toBe("medium");
  });

  it("caps findings per file and says so", async () => {
    await writeFile(join(root, "gen.js"), 'const c = require("crypto");\n' + 'c.createCipheriv("des", k, iv);\n'.repeat(600));
    const findings = await scanSource(root);
    expect(findings.filter((f) => f.ruleId === "source/node-crypto/weak-cipher")).toHaveLength(500);
    expect(findings.find((f) => f.ruleId === "source/findings-capped")?.evidence).toBe("gen.js");
    const direct = scanContent("gen.js", 'const c = require("crypto");\n' + 'c.createCipheriv("des", k, iv);\n'.repeat(600));
    expect(direct.find((f) => f.ruleId === "source/findings-capped")?.title).toMatch(/100 further/);
  });
});

describe("resource ceilings count all I/O", () => {
  it("charges binary files to the file and byte budgets", async () => {
    // Audit repro: 50 binaries of 1.9 MB were read but never counted, so
    // {maxTotalBytes: 100_000, maxFiles: 2} still returned no truncation finding.
    for (let i = 0; i < 50; i += 1) {
      await writeFile(join(root, `blob${String(i).padStart(2, "0")}.bin`), Buffer.concat([Buffer.from([0]), Buffer.alloc(20_000, 1)]));
    }
    await writeFile(join(root, "zkey.pem"), PRIVATE_KEY);
    const byFiles = await scanSource(root, { maxFiles: 2 });
    expect(byFiles.find((f) => f.ruleId === "source/scan-truncated")).toBeDefined();
    const byBytes = await scanSource(root, { maxTotalBytes: 100_000 });
    const truncated = byBytes.find((f) => f.ruleId === "source/scan-truncated");
    expect(truncated?.evidence).toMatch(/stopped after \d+ file\(s\) and \d+ byte\(s\)/);
  });

  it("never reads an oversized file, so it costs no byte budget", async () => {
    const huge = await open(join(root, "a-huge.dat"), "w");
    await huge.truncate(50_000_000); // sparse
    await huge.close();
    await writeFile(join(root, "b-key.pem"), PRIVATE_KEY);
    const findings = await scanSource(root, { maxTotalBytes: 10_000 });
    expect(findings.some((f) => f.ruleId === "keys/private-key-block")).toBe(true);
    expect(findings.some((f) => f.ruleId === "source/scan-truncated")).toBe(false);
  });
});

describe("deterministic, repository-relative output", () => {
  it("assigns ids in byte-sorted path order regardless of readdir order", async () => {
    const names = ["zeta.js", "Beta.js", "alpha.js", "_under.js", "mid.js", "Zulu.js", "9lives.js", "a-b.js", "a_b.js", "ab.js"];
    for (const name of names) await writeFile(join(root, name), 'const c = require("crypto");\nc.createCipheriv("des", k, iv);\n');
    const findings = await scanSource(root);
    const order = findings.filter((f) => f.category === "source").map((f) => [f.id, f.location?.path]);
    const sorted = [...names].sort((a, z) => (a < z ? -1 : a > z ? 1 : 0));
    expect(order.map(([, path]) => path)).toEqual(sorted);
    expect(order.map(([id]) => id)).toEqual(sorted.map((_, i) => `CSW-SRC-${String(i + 1).padStart(3, "0")}`));
  });

  it("emits repository-relative, forward-slash paths for a './relative' root", async () => {
    // Audit repro: `scan ./fx1` produced 'fx1/src/app.ts' for source but 'package.json' for deps.
    await mkdir(join(root, "src", "lib"), { recursive: true });
    await writeFile(join(root, "src", "lib", "k.pem"), PRIVATE_KEY);
    const dotted = `./${relative(process.cwd(), root)}`;
    const [key] = await scanSource(dotted);
    expect(key?.location?.path).toBe("src/lib/k.pem");
    expect(key?.evidence).toBe("src/lib/k.pem:1");
  });
});

describe("dependency manifests", () => {
  it("are not read as code by the regex sweep, but are still checked for keys", () => {
    const manifest = JSON.stringify({ dependencies: { jsonwebtoken: "9.0.2" }, config: { mode: "none", alg: "RS256" } });
    expect(scanContent("package.json", manifest)).toEqual([]);
    expect(scanContent("web/package.json", manifest + PRIVATE_KEY).map((f) => f.ruleId)).toEqual(["keys/private-key-block"]);
  });
});

describe("PEM keys", () => {
  const pem = (key: KeyObject): string => key.export({ type: "spki", format: "pem" }).toString();

  it("parses an embedded public key and grades it by its real algorithm and size", () => {
    const rsa2048 = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey;
    const rsa1024 = generateKeyPairSync("rsa", { modulusLength: 1024 }).publicKey;
    const ec = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey;
    const ed = generateKeyPairSync("ed25519").publicKey;
    const f = scanContent("src/keys.ts", [pem(rsa2048), pem(rsa1024), pem(ec), pem(ed)].join("\n"));
    const keys = f.filter((x) => x.ruleId === "keys/public-key-block");
    expect(keys.map((k) => k.algorithm)).toEqual(["RSA-2048", "RSA-1024", "ECDSA-P-256", "Ed25519"]);
    expect(keys.map((k) => k.severity)).toEqual(["medium", "high", "medium", "medium"]);
    expect(keys.every((k) => k.pq_status === "vulnerable" && k.confidence === "confirmed")).toBe(true);
  });

  it("marks a post-quantum public key safe instead of 'RSA/EC vulnerable'", () => {
    let mldsa: KeyObject;
    try {
      mldsa = generateKeyPairSync("ml-dsa-65").publicKey;
    } catch {
      return; // this Node/OpenSSL build has no ML-DSA
    }
    const [key] = scanContent("src/keys.ts", pem(mldsa));
    expect(key?.algorithm).toBe("ML-DSA-65");
    expect(key?.pq_status).toBe("safe");
    expect(key?.severity).toBe("info");
  });

  it("finds a private key inside a JSON-escaped service-account file", () => {
    const json = JSON.stringify({ type: "service_account", private_key: `-----BEGIN PRIVATE KEY-----\n${PEM_BODY}\n-----END PRIVATE KEY-----\n` });
    const [key] = scanContent("deploy/sa.json", json);
    expect(key?.ruleId).toBe("keys/private-key-block");
    expect(key?.severity).toBe("critical");
    expect(key?.references?.map((r) => r.label).join(" ")).toMatch(/CWE-321/);
  });

  it("finds an indented key in YAML and a PGP private key block", () => {
    const yaml = `tls:\n  key: |\n    -----BEGIN EC PRIVATE KEY-----\n    ${PEM_BODY}\n    -----END EC PRIVATE KEY-----\n`;
    const pgp = `-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\n${PEM_BODY}\n=abcd\n-----END PGP PRIVATE KEY BLOCK-----\n`;
    expect(scanContent("deploy/values.yaml", yaml).find((x) => x.ruleId === "keys/private-key-block")).toBeDefined();
    expect(scanContent("keys/secret.asc", pgp).find((x) => x.ruleId === "keys/private-key-block")).toBeDefined();
  });
});
