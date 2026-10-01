import { performance } from "node:perf_hooks";
import { describe, expect, it } from "vitest";
import { scanContent } from "../src/scanners/source";
import { parsePnpmLock, parseYarnLock } from "../src/scanners/deps/parsers/npm";
import { parsePyproject, parseRequirementsTxt } from "../src/scanners/deps/parsers/python";
import { parseCargoLock } from "../src/scanners/deps/parsers/cargo";
import { parseToml } from "../src/scanners/deps/parsers/toml";

/**
 * Catastrophic-backtracking regressions. Each input is adversarial but sized
 * like a real file, and each budget is generous (tens of times the linear
 * cost) yet finite: the old patterns took from tens of seconds to hours here.
 */
const BUDGET_MS = 1_500;

function timed(run: () => unknown): number {
  const start = performance.now();
  run();
  return performance.now() - start;
}

const PEM_BODY = "MIIBOgIBAAJBAKbogusexamplecontentnotarealkeyAAAAAAAAAAAAAAAAAAAAAA";

describe("ReDoS: private-key PEM scan", () => {
  it("stays linear on a BEGIN marker followed by a long run of newlines", () => {
    // The old pattern was cubic here: 4,000 newlines took 20 s, 200,000 is hours.
    const hostile = `-----BEGIN PRIVATE KEY-----${"\n".repeat(200_000)}`;
    expect(timed(() => scanContent("README.md", hostile))).toBeLessThan(BUDGET_MS);
  });

  it("scans the 6 KB file that used to hang the CLI", () => {
    const hostile = `# notes\n-----BEGIN RSA PRIVATE KEY-----${"\n".repeat(6_000)}`;
    expect(timed(() => scanContent("README.md", hostile))).toBeLessThan(BUDGET_MS);
  });

  it("stays linear on many BEGIN markers sharing header-looking lines and one long body", () => {
    const marker = "-----BEGIN PRIVATE KEY-----";
    const hostile = `${marker}\n${`A: ${marker}\n`.repeat(20_000)}${"A".repeat(60_000)}`;
    expect(timed(() => scanContent("keys.txt", hostile))).toBeLessThan(BUDGET_MS);
  });

  it("still finds a real key after the adversarial prefix", () => {
    const hostile = `-----BEGIN PRIVATE KEY-----${"\n".repeat(50_000)}\n-----BEGIN RSA PRIVATE KEY-----\n${PEM_BODY}\n-----END RSA PRIVATE KEY-----\n`;
    const keys = scanContent("keys.txt", hostile).filter((f) => f.category === "keys");
    expect(keys).toHaveLength(1);
    expect(keys[0]?.location?.line).toBe(50_002);
  });
});

describe("ReDoS: weak-cipher scan", () => {
  it("stays linear on a long cipher-name-shaped token", () => {
    // Old pattern: 30 KB took ~200 ms and doubled-size inputs took 4x; 600 KB is over a minute.
    const hostile = `createCipher("${"des".repeat(200_000)}`;
    expect(timed(() => scanContent("legacy.txt", hostile))).toBeLessThan(BUDGET_MS);
  });
});

describe("ReDoS: line-number lookup", () => {
  it("does not rescan the file for every finding", () => {
    // 450 findings after 4 MB of filler: the old per-finding rescan read ~3.6 GB of characters.
    const filler = "// filler line that keeps the parser busy\n".repeat(100_000);
    const hits = 'createHash("md5");\n'.repeat(450);
    const content = filler + hits;
    let findings: ReturnType<typeof scanContent> = [];
    const elapsed = timed(() => {
      findings = scanContent("bundle.js", content);
    });
    expect(findings.filter((f) => /md5/i.test(f.title)).length).toBeGreaterThan(0);
    expect(findings[0]?.location?.line).toBe(100_001);
    expect(elapsed).toBeLessThan(BUDGET_MS);
  });
});

describe("ReDoS: dependency manifests", () => {
  it("parses a requirements.txt line with a long run of spaces linearly", () => {
    // Old `split(/\s+#/)`: 80 KB took 3 s; 200 KB is ~20 s.
    const hostile = `a${" ".repeat(200_000)}x\nrsa==4.9 # pinned\n`;
    let deps: ReturnType<typeof parseRequirementsTxt> = [];
    const elapsed = timed(() => {
      deps = parseRequirementsTxt(hostile, "requirements.txt");
    });
    expect(elapsed).toBeLessThan(BUDGET_MS);
    expect(deps.find((d) => d.name === "rsa")?.version).toBe("4.9");
  });

  it("strips an unterminated extras bracket run linearly", () => {
    const hostile = `a${"[".repeat(200_000)}\n`;
    expect(timed(() => parseRequirementsTxt(hostile, "requirements.txt"))).toBeLessThan(BUDGET_MS);
  });

  it("parses a pnpm-lock.yaml full of blank lines linearly", () => {
    // Old multiline `^\s{2,}`: 40 KB took 1.4 s; 200 KB is ~35 s.
    const hostile = `lockfileVersion: '9.0'\n${"\n".repeat(200_000)}packages:\n\n  jsonwebtoken@9.0.2:\n`;
    let deps: ReturnType<typeof parsePnpmLock> = [];
    const elapsed = timed(() => {
      deps = parsePnpmLock(hostile, "pnpm-lock.yaml");
    });
    expect(elapsed).toBeLessThan(BUDGET_MS);
    expect(deps.find((d) => d.name === "jsonwebtoken")?.version).toBe("9.0.2");
  });
});

describe("ReDoS: TOML and yarn.lock readers", () => {
  it("stays linear on unterminated and pathological TOML", () => {
    for (const hostile of [
      `a = "${"x".repeat(200_000)}`,
      `a = """${"\\ \n".repeat(50_000)}`,
      `a = '''${"x".repeat(200_000)}`,
      `[${"a.".repeat(100_000)}`,
      "[".repeat(200_000),
      `v = ${"1".repeat(200_000)} x`,
      `dependencies = [${'"a[b]", '.repeat(20_000)}`,
    ]) {
      expect(timed(() => parseToml(hostile)), hostile.slice(0, 20)).toBeLessThan(BUDGET_MS);
    }
  });

  it("parses a large lockfile and a pyproject with thousands of entries linearly", () => {
    const lock = '[[package]]\nname = "ring"\nversion = "0.16.20"\n\n'.repeat(20_000);
    let packages = 0;
    expect(timed(() => (packages = parseCargoLock(lock, "Cargo.lock").length))).toBeLessThan(BUDGET_MS);
    expect(packages).toBe(1);
    const pyproject = `[project]\ndependencies = [${Array.from({ length: 20_000 }, (_, i) => `"pkg${i}[x]>=1"`).join(", ")}]\n`;
    expect(timed(() => parsePyproject(pyproject, "pyproject.toml"))).toBeLessThan(BUDGET_MS);
  });

  it("parses a yarn.lock with huge header and version lines linearly", () => {
    const hostile = `${"a@1, ".repeat(40_000)}:\n  version ${" ".repeat(200_000)}x\n`;
    expect(timed(() => parseYarnLock(hostile, "yarn.lock"))).toBeLessThan(BUDGET_MS);
  });
});
