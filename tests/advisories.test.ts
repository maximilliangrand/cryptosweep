import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { matchDeps, scanDeps } from "../src/scanners/deps";
import type { ParsedDep } from "../src/scanners/deps";
import { annotateWithAdvisories } from "../src/scanners/deps/advisories";

type Init = { method: string; headers: Record<string, string>; body: string; signal: AbortSignal };
type Fetched = { ok: boolean; status: number; json: () => Promise<unknown> };

/** A stub fetch that returns a canned JSON body. */
function stubFetch(body: unknown, ok = true, status = 200): (u: string, i: Init) => Promise<Fetched> {
  return () => Promise.resolve({ ok, status, json: () => Promise.resolve(body) });
}

const osvFixture = JSON.parse(
  readFileSync(fileURLToPath(new URL("./fixtures/deps/osv-batch-response.json", import.meta.url)), "utf8"),
) as unknown;

const dep = (over: Partial<ParsedDep>): ParsedDep => ({
  name: "rsa",
  version: "4.9",
  ecosystem: "python",
  manifestPath: "requirements.txt",
  ...over,
});

afterEach(() => vi.restoreAllMocks());

describe("annotateWithAdvisories", () => {
  it("appends OSV references and a recommendation line without touching the PQ verdict", async () => {
    const deps = [dep({})];
    const findings = matchDeps(deps);
    const before = findings[0];
    const [after] = await annotateWithAdvisories(findings, deps, {
      enabled: true,
      endpoint: "http://test/osv",
      fetchImpl: stubFetch({ results: [{ vulns: [{ id: "CVE-2016-1000027" }] }] }),
    });

    expect(after?.severity).toBe(before?.severity);
    expect(after?.pq_status).toBe(before?.pq_status);
    expect(after?.confidence).toBe(before?.confidence);
    expect(after?.title).toBe(before?.title);
    expect(after?.references?.some((r) => r.label.includes("CVE-2016-1000027"))).toBe(true);
    expect(after?.recommendation).toMatch(/Known advisories \(not PQ\): CVE-2016-1000027\./);
  });

  it("dedupes, sorts, and caps advisory ids at 5", async () => {
    const deps = [dep({})];
    const findings = matchDeps(deps);
    const [after] = await annotateWithAdvisories(findings, deps, {
      enabled: true,
      endpoint: "http://test/osv",
      fetchImpl: stubFetch(osvFixture),
    });
    const advisories = (after?.references ?? []).filter((r) => r.label.includes("known advisory"));
    expect(advisories).toHaveLength(5); // 7 raw, 1 duplicate -> 6 unique -> capped to 5
    expect(advisories[0]?.label).toContain("CVE-2019-0004"); // sorted ascending
  });

  it("never queries a dependency whose version is a range, not a pin", async () => {
    const deps = [dep({ name: "jsonwebtoken", ecosystem: "npm", version: "^9.0.0", manifestPath: "package.json" })];
    const findings = matchDeps(deps);
    const spy = vi.fn(stubFetch({ results: [] }));
    const out = await annotateWithAdvisories(findings, deps, { enabled: true, endpoint: "http://test/osv", fetchImpl: spy });
    expect(spy).not.toHaveBeenCalled();
    expect(out).toEqual(findings);
  });

  it("maps ecosystems to OSV names in the request body", async () => {
    const deps = [
      dep({ name: "elliptic", ecosystem: "npm", version: "6.5.4", manifestPath: "package.json" }),
      dep({ name: "rsa", ecosystem: "python", version: "4.9", manifestPath: "requirements.txt" }),
      dep({ name: "ed25519-dalek", ecosystem: "cargo", version: "2.1.0", manifestPath: "Cargo.toml" }),
    ];
    const findings = matchDeps(deps);
    let ecosystems: string[] = [];
    const capture = (_u: string, init: Init): Promise<Fetched> => {
      const body = JSON.parse(init.body) as { queries: Array<{ package: { ecosystem: string } }> };
      ecosystems = body.queries.map((q) => q.package.ecosystem);
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ results: findings.map(() => ({})) }) });
    };
    await annotateWithAdvisories(findings, deps, { enabled: true, endpoint: "http://test/osv", fetchImpl: capture });
    expect(ecosystems).toEqual(["npm", "PyPI", "crates.io"]);
  });

  it("fails closed on network error, non-200, and unparseable body", async () => {
    const deps = [dep({})];
    const findings = matchDeps(deps);
    vi.spyOn(process.stderr, "write").mockReturnValue(true);

    const reject = (): Promise<Fetched> => Promise.reject(new Error("boom"));
    expect(await annotateWithAdvisories(findings, deps, { enabled: true, endpoint: "http://t", fetchImpl: reject })).toEqual(findings);
    expect(await annotateWithAdvisories(findings, deps, { enabled: true, endpoint: "http://t", fetchImpl: stubFetch({}, false, 503) })).toEqual(findings);
    const badJson = (): Promise<Fetched> => Promise.resolve({ ok: true, status: 200, json: () => Promise.reject(new Error("bad")) });
    expect(await annotateWithAdvisories(findings, deps, { enabled: true, endpoint: "http://t", fetchImpl: badJson })).toEqual(findings);
  });
});

describe("annotateWithAdvisories joins on structured identity", () => {
  const vuln = stubFetch({ results: [{ vulns: [{ id: "GHSA-test" }] }] });
  const options = { enabled: true, endpoint: "http://test/osv", fetchImpl: vuln };

  it("does not depend on the evidence string's display format", async () => {
    const deps = [dep({})];
    const [finding] = matchDeps(deps);
    if (!finding) throw new Error("rsa not flagged");
    const reworded = { ...finding, evidence: `rsa 4.9 declared in requirements.txt` };
    const [after] = await annotateWithAdvisories([reworded], deps, options);
    expect(after?.recommendation).toMatch(/GHSA-test/);
  });

  it("uses a finding's structured dependency version to pick between duplicates", async () => {
    const deps = [dep({ version: "4.8" }), dep({ version: "4.9" })];
    const findings = matchDeps(deps);
    const queried: string[] = [];
    const capture = (_u: string, init: Init): Promise<Fetched> => {
      const body = JSON.parse(init.body) as { queries: Array<{ version: string }> };
      queried.push(...body.queries.map((q) => q.version));
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ results: body.queries.map(() => ({})) }) });
    };
    const structured = findings.map((f, i) => ({ ...f, dependency: { ecosystem: "python", name: "rsa", version: deps[i]?.version } }));
    await annotateWithAdvisories(structured, deps, { enabled: true, endpoint: "http://t", fetchImpl: capture });
    expect(queried.sort()).toEqual(["4.8", "4.9"]);
  });

  it("fails closed when the join is ambiguous", async () => {
    const deps = [dep({ version: "4.8" }), dep({ version: "4.9" })];
    const findings = matchDeps(deps);
    const spy = vi.fn(vuln);
    const out = await annotateWithAdvisories(findings, deps, { enabled: true, endpoint: "http://t", fetchImpl: spy });
    expect(spy).not.toHaveBeenCalled();
    expect(out).toEqual(findings);
  });

  it("reports lookup failures through an injected sink instead of stderr", async () => {
    const deps = [dep({})];
    const findings = matchDeps(deps);
    const stderr = vi.spyOn(process.stderr, "write").mockReturnValue(true);
    const warnings: string[] = [];
    await annotateWithAdvisories(findings, deps, {
      enabled: true,
      endpoint: "http://t",
      fetchImpl: stubFetch({}, false, 503),
      onWarning: (message) => warnings.push(message),
    });
    expect(warnings).toEqual(["OSV advisory lookup failed (HTTP 503); reporting PQ findings only."]);
    expect(stderr).not.toHaveBeenCalled();
  });
});

describe("scanDeps advisories gating", () => {
  it("makes no network call when advisories are disabled", async () => {
    const root = fileURLToPath(new URL("./fixtures/deps/", import.meta.url));
    const throwFetch = (): Promise<Fetched> => {
      throw new Error("network must not be touched");
    };
    // Disabled: annotate is never invoked, so the throwing fetch is never reached.
    await expect(scanDeps(root, { advisories: { enabled: false, fetchImpl: throwFetch } })).resolves.toBeDefined();
  });
});
