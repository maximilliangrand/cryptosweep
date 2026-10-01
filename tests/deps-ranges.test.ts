/**
 * Version-aware dependency matching judges a declaration as the range it is.
 * It used to read the first number at high confidence: `rustls = "0.23"` (a
 * Cargo caret that resolves to the latest 0.23.x) was "predates 0.23.22",
 * `cryptography[ssh]>=41` got the same info/transitional verdict as 48.0.0,
 * and a requirements line continuation left `paramiko@3.4.0 \` in evidence.
 */
import { describe, expect, it } from "vitest";
import { matchDeps } from "../src/scanners/deps";
import type { ParsedDep } from "../src/scanners/deps";
import { annotateWithAdvisories } from "../src/scanners/deps/advisories";
import { parseCargoToml } from "../src/scanners/deps/parsers/cargo";
import { parsePipfile, parsePyproject, parseRequirementsTxt } from "../src/scanners/deps/parsers/python";
import { judgeRange } from "../src/scanners/deps/version-range";

const RUSTLS_FIXED = [0, 23, 22];

describe("judgeRange", () => {
  it.each([
    ["0.21.0", { kind: "below", exact: true }],
    ["=0.23.5", { kind: "below", exact: true }],
    ["^0.21", { kind: "below", exact: false }],
    ["^0.23.5", { kind: "either" }],
    ["~0.23.1", { kind: "either" }],
    ["0.23", { kind: "either" }],
    ["0.23.x", { kind: "either" }],
    [">=0.21, <0.23.22", { kind: "below", exact: false }],
    [">=0.21, <=0.23.22", { kind: "either" }],
    [">=0.21", { kind: "either" }],
    ["*", { kind: "either" }],
    ["0.23.27", { kind: "at-or-above" }],
    ["^0.23.22", { kind: "at-or-above" }],
    [">= 0.24", { kind: "at-or-above" }],
    ["0.21.0 || 0.23.30", { kind: "either" }],
    ["0.20 - 0.22", { kind: "below", exact: false }],
    ["0.23.0-rc.1", { kind: "below", exact: true }],
  ])("%s against 0.23.22", (spec, verdict) => {
    expect(judgeRange(spec, RUSTLS_FIXED)).toEqual(verdict);
  });

  it.each([
    [">=41", { kind: "either" }],
    ["~=41.0", { kind: "below", exact: false }],
    ["==41.*", { kind: "below", exact: false }],
    ["==47.0.0", { kind: "below", exact: true }],
    [">=48,<50", { kind: "at-or-above" }],
    ["!=47.0.1,>=46", { kind: "either" }],
  ])("PEP 440 %s against 48.0.0", (spec, verdict) => {
    expect(judgeRange(spec, [48, 0, 0])).toEqual(verdict);
  });

  it("refuses what it cannot read", () => {
    for (const spec of ["latest", "git+https://example.com/x.git", "workspace:^", "file:../x"]) expect(judgeRange(spec, RUSTLS_FIXED)).toBeNull();
  });
});

describe("dependency findings", () => {
  const find = (deps: ParsedDep[], name: string) => matchDeps(deps).find((f) => f.dependency?.name === name);

  it("does not call a Cargo caret range 'predates'", () => {
    const deps = parseCargoToml('[dependencies]\nrustls = "0.23"\nold = { package = "rustls", version = "0.21" }\n', "Cargo.toml");
    expect(deps.find((d) => d.name === "rustls")?.constraint).toBe("^0.23");
    const finding = find(deps, "rustls");
    expect(finding?.confidence).toBe("low");
    expect(finding?.recommendation).toMatch(/admits releases both before and from 0\.23\.22/);
    expect(finding?.recommendation).toMatch(/lockfile/);
  });

  it("still calls a lockfile pin below fixedIn 'predates', at high confidence", () => {
    const finding = find([{ name: "rustls", version: "0.20.9", ecosystem: "cargo", manifestPath: "Cargo.lock" }], "rustls");
    expect(finding?.confidence).toBe("high");
    expect(finding?.recommendation).toMatch(/rustls 0\.20\.9 predates 0\.23\.22/);
  });

  it("gives cryptography below 48.0.0 a classical verdict, and >=41 a low-confidence one", () => {
    const pinned = find(parseRequirementsTxt("cryptography==42.0.5\n", "requirements.txt"), "cryptography");
    expect(pinned).toMatchObject({ severity: "medium", pq_status: "vulnerable", confidence: "high" });
    const ranged = find(parsePyproject('[project]\ndependencies = ["cryptography[ssh]>=41"]\n', "pyproject.toml"), "cryptography");
    expect(ranged).toMatchObject({ severity: "medium", pq_status: "vulnerable", confidence: "low" });
    expect(ranged?.recommendation).toMatch(/cryptography >=41 admits releases both before and from 48\.0\.0/);
    const current = find(parseRequirementsTxt("cryptography>=48.0.0\n", "requirements.txt"), "cryptography");
    expect(current).toMatchObject({ severity: "info", pq_status: "transitional" });
  });

  it("reads a Pipfile constraint as the range it is", () => {
    const deps = parsePipfile('[packages]\ncryptography = ">=46"\n', "Pipfile");
    expect(deps[0]).toMatchObject({ version: "46", constraint: ">=46" });
    expect(find(deps, "cryptography")?.confidence).toBe("low");
  });
});

describe("requirements files", () => {
  it("joins backslash continuations and drops per-requirement options", () => {
    const deps = parseRequirementsTxt(
      "paramiko==3.4.0 \\\n    --hash=sha256:aaaa \\\n    --hash=sha256:bbbb\nrsa==4.9 --hash=sha256:cccc\n",
      "requirements.txt",
    );
    expect(deps.map((d) => `${d.name}@${d.version}`)).toEqual(["paramiko@3.4.0", "rsa@4.9"]);
    expect(matchDeps(deps).map((f) => f.evidence)).toEqual(["requirements.txt:paramiko@3.4.0", "requirements.txt:rsa@4.9"]);
  });
});

describe("OSV lookups", () => {
  it("query only declarations that pin one release", async () => {
    const deps: ParsedDep[] = [
      ...parseRequirementsTxt("rsa==4.9\nparamiko>=3.0\n", "requirements.txt"),
      ...parseCargoToml('[dependencies]\nring = "0.17.8"\n', "Cargo.toml"),
    ];
    const bodies: string[] = [];
    await annotateWithAdvisories(matchDeps(deps), deps, {
      enabled: true,
      endpoint: "http://test/osv",
      fetchImpl: (_url, init) => {
        bodies.push(init.body);
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ results: [{ vulns: [] }] }) });
      },
    });
    const queried = bodies.flatMap((b) => (JSON.parse(b) as { queries: Array<{ package: { name: string } }> }).queries.map((q) => q.package.name));
    expect(queried).toEqual(["rsa"]);
  });
});
