import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { lookupEntry, REGISTRY } from "../src/scanners/deps/registry";
import { extractVersion, matchDeps, scanDeps } from "../src/scanners/deps";
import type { ParsedDep } from "../src/scanners/deps";
import { REFS } from "../src/crypto";
import { parsePackageJson, parsePnpmLock } from "../src/scanners/deps/parsers/npm";
import { parsePyproject, parseRequirementsTxt } from "../src/scanners/deps/parsers/python";
import { parseCargoToml } from "../src/scanners/deps/parsers/cargo";

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
