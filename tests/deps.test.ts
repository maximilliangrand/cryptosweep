import { mkdir, mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { lookupEntry, REGISTRY } from "../src/scanners/deps/registry";
import { extractVersion, matchDeps, scanDeps } from "../src/scanners/deps";
import type { ParsedDep } from "../src/scanners/deps";
import { REFS } from "../src/crypto";
import { parsePackageJson, parsePackageLock, parsePnpmLock, parseYarnLock } from "../src/scanners/deps/parsers/npm";
import {
  normalizePythonName,
  parsePipfile,
  parsePipfileLock,
  parsePyproject,
  parsePythonLock,
  parseRequirementsTxt,
} from "../src/scanners/deps/parsers/python";
import { parseCargoLock, parseCargoToml } from "../src/scanners/deps/parsers/cargo";
import { parseToml } from "../src/scanners/deps/parsers/toml";

const FIXTURES = fileURLToPath(new URL("./fixtures/deps/", import.meta.url));
const read = (name: string): string => readFileSync(join(FIXTURES, name), "utf8");

describe("registry sanity", () => {
  it("has no duplicate (name, ecosystem) entries", () => {
    const keys = REGISTRY.map((e) => `${e.ecosystem}:${e.name}`);
    expect(new Set(keys).size).toBe(keys.length);
  });
});

describe("npm parser", () => {
  it("finds the two PQ-flagged deps in sample-package.json", () => {
    const deps = parsePackageJson(read("sample-package.json"), "package.json");
    const findings = matchDeps(deps);

    expect(findings).toHaveLength(2);

    const jwt = findings.find((f) => f.evidence.includes("jsonwebtoken"));
    const cryptojs = findings.find((f) => f.evidence.includes("crypto-js"));
    const jwtEntry = lookupEntry("jsonwebtoken", "npm");
    const cryptojsEntry = lookupEntry("crypto-js", "npm");

    expect(jwt).toBeDefined();
    expect(cryptojs).toBeDefined();
    expect(jwt?.severity).toBe(jwtEntry?.severity);
    expect(jwt?.pq_status).toBe(jwtEntry?.pq_status);
    expect(cryptojs?.severity).toBe(cryptojsEntry?.severity);
    expect(cryptojs?.pq_status).toBe(cryptojsEntry?.pq_status);
  });

  it("returns zero findings for clean-package.json (no false positives)", () => {
    const deps = parsePackageJson(read("clean-package.json"), "package.json");
    expect(matchDeps(deps)).toEqual([]);
  });

  it("extracts resolved versions from a pnpm-lock fixture", () => {
    const deps = parsePnpmLock(read("sample-pnpm-lock.yaml"), "pnpm-lock.yaml");
    const jsonwebtoken = deps.find((d) => d.name === "jsonwebtoken");
    expect(jsonwebtoken?.version).toBe("9.0.2");
  });
});

describe("python parser", () => {
  it("flags `rsa` from a requirements.txt fixture", () => {
    const deps = parseRequirementsTxt(read("sample-requirements.txt"), "requirements.txt");
    const findings = matchDeps(deps);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain("rsa@4.9");
    expect(findings[0]?.severity).toBe(lookupEntry("rsa", "python")?.severity);
  });

  it("flags `pyjwt` from a pyproject.toml [project] table", () => {
    const deps = parsePyproject(read("sample-pyproject.toml"), "pyproject.toml");
    const findings = matchDeps(deps);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain("pyjwt@");
    expect(findings[0]?.pq_status).toBe(lookupEntry("pyjwt", "python")?.pq_status);
  });
});

describe("cargo parser", () => {
  it("flags the cargo `rsa` crate without confusing it for the npm or pypi `rsa` package", () => {
    const deps = parseCargoToml(read("sample-Cargo.toml"), "Cargo.toml");
    const findings = matchDeps(deps);
    expect(findings).toHaveLength(1);
    const finding = findings[0];
    expect(finding?.evidence).toContain("Cargo.toml:rsa@0.9");
    const cargoEntry = lookupEntry("rsa", "cargo");
    expect(finding?.severity).toBe(cargoEntry?.severity);
    expect(finding?.pq_status).toBe(cargoEntry?.pq_status);
    // Same name, different ecosystem — must not pull npm/python recommendation.
    expect(finding?.recommendation).toBe(cargoEntry?.recommendation);
  });
});

describe("registry provenance & expansion", () => {
  it("gives every vulnerable/transitional entry at least one provenance reference", () => {
    const missing = REGISTRY.filter(
      (e) => (e.pq_status === "vulnerable" || e.pq_status === "transitional") && !(e.references && e.references.length),
    );
    expect(missing.map((e) => `${e.ecosystem}:${e.name}`)).toEqual([]);
  });

  it("ensures every fixedIn is a parseable version", () => {
    for (const e of REGISTRY) {
      if (e.fixedIn) expect(extractVersion(e.fixedIn), `${e.name} fixedIn`).not.toBeNull();
    }
  });

  it("merges entry-specific provenance with the generic standards, deduped", () => {
    const [f] = matchDeps([{ name: "rustls", version: "0.21.0", ecosystem: "cargo", manifestPath: "Cargo.toml" }]);
    const labels = (f?.references ?? []).map((r) => r.label);
    expect(labels).toContain(REFS.hybridKex.label); // entry-specific
    expect(labels).toContain(REFS.cnsa2.label); // generic (vulnerable)
    expect(labels).toContain(REFS.ir8547.label);
    expect(new Set(labels).size).toBe(labels.length); // no duplicate labels
  });

  it("flags the newly-added libraries with the expected posture", () => {
    const deps: ParsedDep[] = [
      { name: "elliptic", version: "6.5.4", ecosystem: "npm", manifestPath: "package.json" },
      { name: "ecdsa", version: "0.18.0", ecosystem: "python", manifestPath: "requirements.txt" },
      { name: "ed25519-dalek", version: "2.1.0", ecosystem: "cargo", manifestPath: "Cargo.toml" },
    ];
    const findings = matchDeps(deps);
    expect(findings).toHaveLength(3);
    expect(findings.every((f) => f.pq_status === "vulnerable")).toBe(true);
    // Classical-by-nature (no fixedIn) => version-independent medium confidence.
    expect(findings.every((f) => f.confidence === "medium")).toBe(true);
  });
});

describe("version-aware matching", () => {
  const rustls = (version: string): ParsedDep[] => [
    { name: "rustls", version, ecosystem: "cargo", manifestPath: "Cargo.toml" },
  ];

  it("extractVersion strips range operators to a comparable version", () => {
    expect(extractVersion("^9.0.0")).toEqual([9, 0, 0]);
    expect(extractVersion(">=1.2")).toEqual([1, 2]);
    expect(extractVersion("~=42.0.1")).toEqual([42, 0, 1]);
    expect(extractVersion("")).toBeNull();
    expect(extractVersion("latest")).toBeNull();
  });

  it("flags a rustls install below fixedIn as vulnerable / high confidence", () => {
    const [f] = matchDeps(rustls("0.21.0"));
    expect(f?.pq_status).toBe("vulnerable");
    expect(f?.confidence).toBe("high");
  });

  it("downgrades a rustls install at/above fixedIn to transitional / info", () => {
    const [f] = matchDeps(rustls("0.23.27"));
    expect(f?.pq_status).toBe("transitional");
    expect(f?.severity).toBe("info");
    expect(f?.recommendation).toMatch(/at or above 0\.23\.22/);
  });

  it("flags conservatively at low confidence when the version cannot be resolved", () => {
    const [f] = matchDeps(rustls(""));
    expect(f?.pq_status).toBe("vulnerable");
    expect(f?.confidence).toBe("low");
  });
});

describe("scanDeps orchestrator", () => {
  let root: string;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), "csw-deps-test-"));
    await writeFile(join(root, "package.json"), read("sample-package.json"), "utf8");
    await writeFile(join(root, "requirements.txt"), read("sample-requirements.txt"), "utf8");
    await writeFile(join(root, "Cargo.toml"), read("sample-Cargo.toml"), "utf8");
  });

  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("aggregates findings across npm, python, and cargo manifests", async () => {
    const findings = await scanDeps(root);
    // 2 (npm: jsonwebtoken + crypto-js) + 1 (python: rsa) + 1 (cargo: rsa) = 4.
    expect(findings).toHaveLength(4);
    expect(findings.every((f) => f.category === "deps")).toBe(true);
    expect(findings.every((f) => /^CSW-DEP-\d{3}$/.test(f.id))).toBe(true);
    const evidence = findings.map((f) => f.evidence).join("\n");
    expect(evidence).toContain("package.json:jsonwebtoken@");
    expect(evidence).toContain("requirements.txt:rsa@4.9");
    expect(evidence).toContain("Cargo.toml:rsa@0.9");
  });
});

const names = (deps: readonly ParsedDep[]): string[] => deps.map((d) => d.name);
const versionOf = (deps: readonly ParsedDep[], name: string): string | undefined => deps.find((d) => d.name === name)?.version;

describe("TOML reader", () => {
  it("handles tables, dotted and quoted keys, arrays of tables and inline tables", () => {
    const doc = parseToml(
      [
        "title = 'x' # comment",
        '[a.b."c.d"]',
        "k = 1",
        "x.y = true",
        "[[pkg]]",
        'name = "one"',
        "[[pkg]]",
        'name = "two"',
        'inline = { version = "1.0", features = ["a", "b"], nested = { deep = [1, [2, 3]] } }',
        "[pkg.meta]",
        "n = 2",
      ].join("\n"),
    );
    expect(doc.title).toBe("x");
    expect(doc.a).toEqual({ b: { "c.d": { k: 1, x: { y: true } } } });
    expect(doc.pkg).toEqual([
      { name: "one" },
      { name: "two", inline: { version: "1.0", features: ["a", "b"], nested: { deep: [1, [2, 3]] } }, meta: { n: 2 } },
    ]);
  });

  it("reads every string form, including brackets and quotes inside strings", () => {
    const doc = parseToml(
      [
        'basic = "a]b\\"c\\u00e9"',
        "literal = 'C:\\path'",
        'multi = """',
        'line one \\',
        '   continues"""',
        "raw = '''",
        "keep [this] as-is'''",
        'list = [ "x[y]",',
        "  # a comment",
        "  'z', ]",
        "when = 1979-05-27 07:32:00Z",
      ].join("\n"),
    );
    expect(doc.basic).toBe('a]b"cé');
    expect(doc.literal).toBe("C:\\path");
    expect(doc.multi).toBe("line one continues");
    expect(doc.raw).toBe("keep [this] as-is");
    expect(doc.list).toEqual(["x[y]", "z"]);
    expect(doc.when).toBe("1979-05-27 07:32:00Z");
  });

  it("skips a malformed line instead of dropping the rest of the file", () => {
    const doc = parseToml('[dependencies]\nbroken = = "1"\nrsa = "0.9"\n[bad\nring = "0.17"\n[dev-dependencies]\nproptest = "1"');
    expect(doc.dependencies).toEqual({ rsa: "0.9" });
    expect(doc["dev-dependencies"]).toEqual({ proptest: "1" });
  });

  it("treats __proto__ as an ordinary key and bounds nesting depth", () => {
    const doc = parseToml(`deep = ${"[".repeat(10_000)}\nafter = 1\n[__proto__]\npolluted = true\n`);
    expect(doc.after).toBe(1);
    expect(Object.getPrototypeOf(doc)).toBeNull();
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(doc["__proto__"]).toEqual({ polluted: true });
  });
});

describe("pyproject.toml (TOML-aware)", () => {
  it("keeps every dependency after an extras bracket", () => {
    // Audit repro: the lazy `[\s\S]*?\]` stopped at the `]` of `[ssh]` and returned [].
    const deps = parsePyproject('[project]\ndependencies = ["cryptography[ssh]>=41", "pyjwt>=2.8", "paramiko>=3"]\n', "pyproject.toml");
    expect(names(deps)).toEqual(["cryptography", "pyjwt", "paramiko"]);
    expect(versionOf(deps, "cryptography")).toBe("41");
  });

  it("reads optional-dependencies, dependency-groups, and Poetry dependencies, dev-dependencies and groups", () => {
    const deps = parsePyproject(
      [
        "[project]",
        'dependencies = ["httpx"]',
        "[project.optional-dependencies]",
        'crypto = ["rsa==4.9"]',
        'jwt = ["python_jose[cryptography]>=3.3"]',
        "[dependency-groups]",
        'test = ["ecdsa>=0.18", { include-group = "crypto" }]',
        "[tool.poetry.dependencies]",
        'python = "^3.11"',
        'pycryptodome = "^3.20"',
        'PyNaCl = { version = "1.5.0", optional = true }',
        "[tool.poetry.dev-dependencies]",
        'paramiko = "^3.4"',
        "[tool.poetry.group.ops.dependencies]",
        'pyOpenSSL = [{ version = "24.0.0", python = "<3.12" }, { version = "24.1.0", python = ">=3.12" }]',
      ].join("\n"),
      "pyproject.toml",
    );
    expect(names(deps)).toEqual(["httpx", "rsa", "python-jose", "ecdsa", "pycryptodome", "pynacl", "paramiko", "pyopenssl"]);
    expect(versionOf(deps, "pyopenssl")).toBe("24.0.0");
    expect(matchDeps(deps).map((f) => f.ruleId)).toEqual([
      "deps/python-rsa",
      "deps/python-python-jose",
      "deps/python-ecdsa",
      "deps/python-pycryptodome",
      "deps/python-pynacl",
      "deps/python-paramiko",
      "deps/python-pyopenssl",
    ]);
  });

  it("normalises names per PEP 503", () => {
    expect(normalizePythonName("Python_Jose")).toBe("python-jose");
    expect(normalizePythonName("zope.interface")).toBe("zope-interface");
    const deps = parseRequirementsTxt("python_jose==3.3.0\nPyJWT==2.8.0\nPyNaCl==1.5.0\n", "requirements.txt");
    expect(matchDeps(deps).map((f) => f.ruleId)).toEqual(["deps/python-python-jose", "deps/python-pyjwt", "deps/python-pynacl"]);
  });
});

describe("Cargo.toml (TOML-aware)", () => {
  it("reads dotted, target-specific and workspace tables, renamed and inherited crates", () => {
    // Audit repro: only `deps/cargo-rustls` came back from this manifest.
    const deps = parseCargoToml(
      [
        "[workspace.dependencies]",
        'ed25519-dalek = "2.1"',
        'p256 = { version = "0.13" }',
        "[dependencies]",
        'rustls = { version = "0.21", default-features = false }',
        'crypto-ring = { package = "ring", version = "0.17" }',
        "p256 = { workspace = true }",
        "[dependencies.x25519-dalek]",
        'version = "2.0"',
        "[target.'cfg(unix)'.dependencies]",
        'openssl = "0.10"',
      ].join("\n"),
      "Cargo.toml",
    );
    expect(names(deps)).toEqual(["rustls", "ring", "p256", "x25519-dalek", "ed25519-dalek", "openssl"]);
    expect(versionOf(deps, "p256")).toBe("0.13");
    expect(matchDeps(deps)).toHaveLength(6);
  });

  it("matches crates.io names with `_` and `-` as equivalent", () => {
    const [f] = matchDeps([{ name: "ed25519_dalek", version: "2.1.0", ecosystem: "cargo", manifestPath: "Cargo.toml" }]);
    expect(f?.ruleId).toBe("deps/cargo-ed25519-dalek");
  });
});

describe("lockfiles", () => {
  it("reads Cargo.lock, including a vulnerable rustls version", () => {
    const deps = parseCargoLock(
      'version = 3\n\n[[package]]\nname = "ring"\nversion = "0.16.20"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n[[package]]\nname = "rustls"\nversion = "0.20.9"\ndependencies = ["ring"]\n',
      "Cargo.lock",
    );
    expect(deps.map((d) => `${d.name}@${d.version}`)).toEqual(["ring@0.16.20", "rustls@0.20.9"]);
    expect(matchDeps(deps).find((f) => f.ruleId === "deps/cargo-rustls")?.confidence).toBe("high"); // below fixedIn
  });

  it("reads poetry.lock and uv.lock", () => {
    const lock = '[[package]]\nname = "PyNaCl"\nversion = "1.5.0"\n\n[[package]]\nname = "cryptography"\nversion = "42.0.5"\n[package.dependencies]\ncffi = ">=1.12"\n';
    expect(parsePythonLock(lock, "poetry.lock").map((d) => `${d.name}@${d.version}`)).toEqual(["pynacl@1.5.0", "cryptography@42.0.5"]);
    expect(parsePythonLock(lock, "uv.lock")).toHaveLength(2);
  });

  it("reads Pipfile and Pipfile.lock", () => {
    expect(names(parsePipfile('[packages]\nrsa = "==4.9"\nrequests = "*"\n[dev-packages]\necdsa = { version = ">=0.18" }\n', "Pipfile"))).toEqual(["rsa", "requests", "ecdsa"]);
    const lock = JSON.stringify({ default: { rsa: { version: "==4.9" } }, develop: { ecdsa: { version: "==0.18.0" } } });
    expect(parsePipfileLock(lock, "Pipfile.lock").map((d) => `${d.name}@${d.version}`)).toEqual(["rsa@4.9", "ecdsa@0.18.0"]);
  });

  it("reads package-lock.json v2/v3, with nested installs and aliases", () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "app", dependencies: { elliptic: "^6.5.4" } },
        "node_modules/elliptic": { version: "6.5.4" },
        "node_modules/a/node_modules/tweetnacl": { version: "1.0.3" },
        "node_modules/forge": { name: "node-forge", version: "1.3.1" },
        "node_modules/local": { resolved: "packages/local", link: true },
        "packages/local": { version: "0.0.0" },
      },
    });
    expect(parsePackageLock(lock, "package-lock.json").map((d) => `${d.name}@${d.version}`)).toEqual([
      "elliptic@6.5.4",
      "tweetnacl@1.0.3",
      "node-forge@1.3.1",
    ]);
  });

  it("reads package-lock.json v1 nested dependencies", () => {
    const lock = JSON.stringify({ lockfileVersion: 1, dependencies: { a: { version: "1.0.0", dependencies: { elliptic: { version: "6.5.4" } } } } });
    expect(names(parsePackageLock(lock, "package-lock.json"))).toEqual(["a", "elliptic"]);
  });

  it("reads yarn.lock v1 and berry", () => {
    const v1 = [
      "# yarn lockfile v1",
      "",
      '"@noble/curves@^1.2.0", "@noble/curves@^1.4.0":',
      '  version "1.4.0"',
      '  resolved "https://registry.yarnpkg.com/@noble/curves/-/curves-1.4.0.tgz"',
      "",
      "jsonwebtoken@^8.5.1:",
      '  version "8.5.1"',
      "  dependencies:",
      '    jws "^3.2.2"',
    ].join("\n");
    expect(parseYarnLock(v1, "yarn.lock").map((d) => `${d.name}@${d.version}`)).toEqual(["@noble/curves@1.4.0", "jsonwebtoken@8.5.1"]);
    const berry = ['__metadata:', "  version: 8", "", '"jsonwebtoken@npm:^9.0.0":', "  version: 9.0.2", '  resolution: "jsonwebtoken@npm:9.0.2"'].join("\n");
    expect(parseYarnLock(berry, "yarn.lock").map((d) => `${d.name}@${d.version}`)).toEqual(["jsonwebtoken@9.0.2"]);
  });
});

describe("scanDeps coverage and determinism", () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "csw-deps-cov-"));
    // Audit repro (v11): these three files produced 'Findings: 0 ... No quantum-vulnerable primitives detected.'
    await writeFile(join(dir, "pyproject.toml"), '[tool.poetry.dependencies]\npython = "^3.11"\npycryptodome = "^3.20"\nrsa = "^4.9"\n');
    await writeFile(
      join(dir, "package-lock.json"),
      JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/node-forge": { version: "1.3.1" }, "node_modules/elliptic": { version: "6.5.4" } } }),
    );
    await writeFile(join(dir, "Cargo.lock"), '[[package]]\nname = "ring"\nversion = "0.16.20"\n\n[[package]]\nname = "rustls"\nversion = "0.20.9"\n');
    await mkdir(join(dir, "svc"), { recursive: true });
    await writeFile(join(dir, "svc", "go.mod"), "module example.com/svc\n\nrequire golang.org/x/crypto v0.21.0\n");
    await writeFile(join(dir, "svc", "pom.xml"), "<project/>");
    await writeFile(join(dir, "requirements-dev.txt"), "ecdsa==0.18.0\n");
    const huge = await open(join(dir, "svc", "package.json"), "w");
    await huge.truncate(6_000_000); // sparse, over the 5 MB manifest limit
    await huge.close();
  });
  afterAll(async () => rm(dir, { recursive: true, force: true }));

  it("finds lockfile and Poetry dependencies the old parsers missed", async () => {
    const findings = await scanDeps(dir);
    const rules = findings.filter((f) => f.ruleId?.startsWith("deps/") && f.severity !== "info").map((f) => f.ruleId);
    for (const rule of ["deps/python-pycryptodome", "deps/python-rsa", "deps/npm-node-forge", "deps/npm-elliptic", "deps/cargo-ring", "deps/cargo-rustls", "deps/python-ecdsa"]) {
      expect(rules, rule).toContain(rule);
    }
  });

  it("reports unsupported manifests and oversized manifests instead of a silent gap", async () => {
    const findings = await scanDeps(dir);
    expect(findings.find((f) => f.ruleId === "deps/unsupported-manifest")?.evidence).toBe("svc/go.mod, svc/pom.xml");
    expect(findings.find((f) => f.ruleId === "deps/manifest-too-large")?.evidence).toBe("svc/package.json");
    expect(findings.filter((f) => f.severity === "info").every((f) => /^CSW-DEPCOV-\d{3}$/.test(f.id))).toBe(true);
  });

  it("reports truncation when the entry budget runs out", async () => {
    const findings = await scanDeps(dir, { maxEntries: 3 });
    expect(findings.find((f) => f.ruleId === "deps/scan-truncated")).toBeDefined();
  });

  it("orders manifests, and so finding ids, by sorted path", async () => {
    const findings = (await scanDeps(dir)).filter((f) => f.severity !== "info");
    const paths = findings.map((f) => f.location?.path ?? "");
    expect(paths).toEqual([...paths].sort((a, z) => (a < z ? -1 : a > z ? 1 : 0)));
  });
});
