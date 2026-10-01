/**
 * The shared walk policy: dependency, build, virtual-environment and cache
 * directories are skipped by both walkers (and the skip is recorded), non-code
 * binaries and source maps are not coverage gaps, and documentation, test,
 * fixture and example paths are de-rated in both scanners and kept out of the
 * risk ledger.
 */
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { defaultProfile } from "../src/model/estate";
import { assessRisk } from "../src/model/risk";
import { describeCoverage, scanLocalDir } from "../src/orchestrate";
import type { Finding } from "../src/report";
import { matchDeps, scanDeps } from "../src/scanners/deps";
import { scanContent, scanSource } from "../src/scanners/source";
import { directoryContext } from "../src/scanners/walk-policy";

const TODAY = "2026-10-01T00:00:00.000Z";

let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "csw-policy-"));
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

async function put(relPath: string, content: string | Buffer): Promise<void> {
  const full = join(root, relPath);
  await mkdir(join(full, ".."), { recursive: true });
  await writeFile(full, content);
}

const PYJWT = 'import jwt\njwt.encode(payload, key, algorithm="RS256")\n';
const SITE = ".venv/lib/python3.12/site-packages";

describe("virtual environments and caches are not the project's code", () => {
  beforeEach(async () => {
    await put("app/main.py", "print('no crypto here')\n");
    await put(".venv/pyvenv.cfg", "home = /usr/bin\n");
    await put(`${SITE}/jwt/api_jws.py`, PYJWT);
    await put(`${SITE}/requests-2.32.3.dist-info/requirements.txt`, "rsa==4.9\n");
    await put(`${SITE}/__pycache__/x.cpython-312.pyc`, Buffer.from([0x00, 0x0d, 0x0d, 0x0a]));
    // A virtual environment under any name is recognised by its pyvenv.cfg.
    await put("env/pyvenv.cfg", "home = /usr/bin\n");
    await put("env/lib/site-packages/rsa/key.py", "from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537, key_size=1024)\n");
    // So is any directory tagged per the Cache Directory Tagging Specification.
    await put("toolcache/CACHEDIR.TAG", "Signature: 8a477f597d28d172789f06886806bc55\n");
    await put("toolcache/key.js", 'require("crypto").createHash("md5");\n');
  });

  it("the source walk reports nothing from inside them, and records the skip", async () => {
    const findings = await scanSource(root);
    const located = findings.filter((f) => f.location?.path !== undefined);
    expect(located).toEqual([]);
    const skipped = findings.find((f) => f.ruleId === "source/directories-skipped");
    expect(skipped?.evidence).toBe(".venv, env, toolcache");
    expect(skipped?.severity).toBe("info");
  });

  it("the dependency walk skips them too", async () => {
    expect(await scanDeps(root)).toEqual([]);
  });

  it("the coverage stays complete and names what was skipped by design", async () => {
    const findings = await scanLocalDir(root);
    const [source] = describeCoverage({ kind: "path", dir: root }, findings);
    expect(source?.complete).toBe(true);
    expect(source?.scope).toMatch(/skipped by design: 3 dependency, build, virtual-environment or cache/);
  });

  it("a virtual environment scanned directly is included", async () => {
    const findings = await scanSource(join(root, ".venv"));
    expect(findings.some((f) => f.location?.path === "lib/python3.12/site-packages/jwt/api_jws.py")).toBe(true);
  });
});

describe("binaries and generated files", () => {
  const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00]), Buffer.alloc(64, 1)]);
  const DER = Buffer.concat([Buffer.from([0x30, 0x82, 0x00]), Buffer.alloc(64, 2)]);

  it("does not count images, fonts or bytecode as a coverage gap", async () => {
    await put("assets/logo.png", PNG);
    await put("assets/font.woff2", PNG);
    await put("mod.wasm", PNG);
    const findings = await scanLocalDir(root);
    expect(findings.find((f) => f.ruleId === "source/binary-skipped")).toBeUndefined();
    expect(findings.find((f) => f.ruleId === "source/non-code-skipped")?.evidence).toBe("assets/font.woff2, assets/logo.png, mod.wasm");
    const [source] = describeCoverage({ kind: "path", dir: root }, findings);
    expect(source?.complete).toBe(true);
  });

  it("still counts key stores and unknown binaries as a gap", async () => {
    await put("certs/server.der", DER);
    await put("keys/store.p12", DER);
    await put("blob.bin", DER);
    const findings = await scanLocalDir(root);
    expect(findings.find((f) => f.ruleId === "source/binary-skipped")?.evidence).toBe("blob.bin, certs/server.der, keys/store.p12");
    const [source] = describeCoverage({ kind: "path", dir: root }, findings);
    expect(source?.complete).toBe(false);
  });

  it("skips source maps instead of reading their embedded sources as code", async () => {
    // A bundle's source map repeats every string of the original sources, so
    // scanning it double-counted them (and read `display: "none"` as JWT none).
    await put(
      "public/app.js.map",
      JSON.stringify({ version: 3, sourcesContent: ['const jwt = require("jsonwebtoken"); jwt.sign(p, k, { algorithm: "RS256" });'] }),
    );
    const findings = await scanSource(root);
    expect(findings.filter((f) => f.location?.path)).toEqual([]);
    expect(findings.find((f) => f.ruleId === "source/non-code-skipped")?.evidence).toBe("public/app.js.map");
  });
});

describe("documentation, test, fixture and example paths", () => {
  it("are judged by directory only, so a requirements file is not documentation", () => {
    expect(directoryContext("requirements.txt")).toBeNull();
    expect(directoryContext("tests/fixtures/deps/sample-requirements.txt")).toBe("test");
    expect(directoryContext("examples/app/package.json")).toBe("test");
    expect(directoryContext("docs/requirements.txt")).toBe("docs");
    expect(directoryContext("src/latest/app.py")).toBeNull();
  });

  it("de-rate a dependency manifest under tests/ the way a source match there is de-rated", () => {
    const [prod, fixture] = matchDeps([
      { name: "rsa", version: "4.9", ecosystem: "python", manifestPath: "requirements.txt" },
      { name: "rsa", version: "4.9", ecosystem: "python", manifestPath: "tests/fixtures/deps/requirements.txt" },
    ]);
    expect(prod?.severity).toBe("high");
    expect(prod?.location).toEqual({ path: "requirements.txt" });
    expect(fixture?.severity).toBe("low");
    expect(fixture?.confidence).toBe("low");
    expect(fixture?.location).toEqual({ path: "tests/fixtures/deps/requirements.txt", context: "test" });
  });

  it("mark source findings with their context", () => {
    const code = 'const crypto = require("crypto");\ncrypto.createDiffieHellman(2048);\n';
    expect(scanContent("src/dh.js", code)[0]?.location).toEqual({ path: "src/dh.js", line: 2 });
    expect(scanContent("test/dh.js", code)[0]?.location).toEqual({ path: "test/dh.js", context: "test", line: 2 });
    expect(scanContent("README.md", code)[0]?.location?.context).toBe("docs");
  });

  it("stay out of the ledger, the act-now count and the obligations", () => {
    const profile = defaultProfile(TODAY, { dataClassId: "legal-privileged" });
    const docs = scanContent("README.md", "| `createDiffieHellman` | crypto.createDiffieHellman(2048) |\n");
    const testKey = scanContent(
      "tests/fixtures/key.pem",
      "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKbogusexamplecontentnotarealkeyAAAAAAAAAAAAAAAAAAAAAA\n-----END RSA PRIVATE KEY-----\n",
    );
    const fixtureDep = matchDeps([{ name: "rsa", version: "4.9", ecosystem: "python", manifestPath: "tests/fixtures/requirements.txt" }]);
    const nonProduction: Finding[] = [...docs, ...testKey, ...fixtureDep];
    expect(nonProduction.length).toBe(3);

    const risk = assessRisk("repo", nonProduction, profile);
    expect(risk.assets).toEqual([]);
    expect(risk.nonProductionAssets).toHaveLength(3);
    expect(risk.ledger).toMatchObject({ exposedAssets: 0, actNowAssets: 0, exposureRiskYears: 0, nonProductionAssets: 3 });
    expect(risk.ledger.byObligation.every((o) => o.assets === 0)).toBe(true);
    expect(risk.ledger.headline).toMatch(/3 asset\(s\) seen only in documentation, tests, fixtures or examples/);
    expect(risk.graph.nodes.some((n) => n.type === "asset")).toBe(false);

    // The same primitive in production code is counted, and is a separate asset.
    const prod = scanContent("src/dh.js", 'const crypto = require("crypto");\ncrypto.createDiffieHellman(2048);\n');
    const mixed = assessRisk("repo", [...prod, ...docs], profile);
    expect(mixed.assets).toHaveLength(1);
    expect(mixed.nonProductionAssets).toHaveLength(1);
    expect(mixed.ledger.exposedAssets).toBe(1);
  });
});
