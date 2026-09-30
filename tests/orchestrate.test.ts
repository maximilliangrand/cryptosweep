import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type * as CloneModule from "../src/clone";
import { cloneRepository } from "../src/clone";
import {
  classifyTarget,
  parseCrqcYear,
  parsePort,
  parseTimeoutMs,
  scanTarget,
} from "../src/orchestrate";
import type { Target } from "../src/orchestrate";

// cloneRepository calls through to the real implementation unless a test
// overrides it, so refusals are exercised for real and nothing touches the network.
vi.mock("../src/clone", async (importOriginal) => {
  const actual = await importOriginal<typeof CloneModule>();
  return { ...actual, cloneRepository: vi.fn(actual.cloneRepository) };
});
const clone = vi.mocked(cloneRepository);

describe("classifyTarget", () => {
  const cases: Array<[string, Target]> = [
    ["example.com", { kind: "host", host: "example.com", port: 443 }],
    ["EXAMPLE.com", { kind: "host", host: "example.com", port: 443 }],
    ["example.com:8443", { kind: "host", host: "example.com", port: 8443 }],
    ["https://example.com:8443/whatever", { kind: "host", host: "example.com", port: 8443 }],
    ["https://www.example.com", { kind: "host", host: "www.example.com", port: 443 }],
    // A hostname with a path is a TLS target, not a GitHub shorthand.
    ["cloudflare.com/cdn-cgi", { kind: "host", host: "cloudflare.com", port: 443 }],
    ["cloudflare.com:8443/cdn-cgi", { kind: "host", host: "cloudflare.com", port: 8443 }],
    // IPv6 literals, bracketed and not, bare and in URLs: never with brackets in `host`.
    ["[::1]:8443", { kind: "host", host: "::1", port: 8443 }],
    ["[2606:4700::6810:84e5]", { kind: "host", host: "2606:4700::6810:84e5", port: 443 }],
    ["2606:4700::6810:84e5", { kind: "host", host: "2606:4700::6810:84e5", port: 443 }],
    ["::1", { kind: "host", host: "::1", port: 443 }],
    ["https://[2606:4700::6810:84e5]/", { kind: "host", host: "2606:4700::6810:84e5", port: 443 }],
    ["https://[::1]:8443/x", { kind: "host", host: "::1", port: 8443 }],
    // Non-canonical numeric hosts are canonicalized the way inet_aton reads them.
    ["0177.0.0.1:8443", { kind: "host", host: "127.0.0.1", port: 8443 }],
    ["2130706433", { kind: "host", host: "127.0.0.1", port: 443 }],
    ["https://github.com", { kind: "host", host: "github.com", port: 443 }],
    [
      "facebook/react",
      {
        kind: "github",
        owner: "facebook",
        repo: "react",
        url: "https://github.com/facebook/react.git",
      },
    ],
    [
      "github.com/facebook/react",
      {
        kind: "github",
        owner: "facebook",
        repo: "react",
        url: "https://github.com/facebook/react.git",
      },
    ],
    [
      "https://github.com/facebook/react.git",
      {
        kind: "github",
        owner: "facebook",
        repo: "react",
        url: "https://github.com/facebook/react.git",
      },
    ],
    [
      "git@github.com:facebook/react.git",
      { kind: "remote", url: "git@github.com:facebook/react.git" },
    ],
    [
      "https://gitlab.com/group/project.git",
      { kind: "remote", url: "https://gitlab.com/group/project.git" },
    ],
    ["ssh://git@git.example.com/x.git", { kind: "remote", url: "ssh://git@git.example.com/x.git" }],
    // Path-shaped input is always a path, whether or not it exists: a mistyped
    // local path must never become a clone request to github.com.
    ["./does-not-exist", { kind: "path", dir: "./does-not-exist" }],
    ["../sibling", { kind: "path", dir: "../sibling" }],
    ["/abs/path", { kind: "path", dir: "/abs/path" }],
    [".", { kind: "path", dir: "." }],
    ["~", { kind: "path", dir: homedir() }],
    ["~/projects", { kind: "path", dir: join(homedir(), "projects") }],
  ];

  it.each(cases)("routes %s", (input, expected) => {
    expect(classifyTarget(input)).toEqual(expected);
  });

  describe("with existing directories that look like hosts or repositories", () => {
    let base: string;
    beforeAll(async () => {
      base = await mkdtemp(join(tmpdir(), "csw-classify-"));
      await mkdir(join(base, "example.com"));
      await mkdir(join(base, "owner", "repo"), { recursive: true });
      await writeFile(join(base, "report.json"), "{}", "utf8");
    });
    afterAll(async () => {
      await rm(base, { recursive: true, force: true });
    });

    it("prefers the local directory", () => {
      expect(classifyTarget("example.com", { baseDir: base })).toEqual({
        kind: "path",
        dir: join(base, "example.com"),
      });
      expect(classifyTarget("owner/repo", { baseDir: base })).toEqual({
        kind: "path",
        dir: join(base, "owner", "repo"),
      });
    });

    it("refuses a file rather than scanning it as a host", () => {
      expect(() => classifyTarget("report.json", { baseDir: base })).toThrow(/is a file/);
    });
  });

  it("rejects input that fits no target kind instead of guessing", () => {
    expect(() => classifyTarget("")).toThrow(/target is required/);
    expect(() => classifyTarget("example.com:0")).toThrow(
      /port in target must be an integer from 1 to 65535/,
    );
    expect(() => classifyTarget("example.com:99999")).toThrow(/port in target/);
    expect(() => classifyTarget("example.com:abc")).toThrow(/port in target/);
    expect(() => classifyTarget("[not-an-address]:443")).toThrow(/Not a valid IPv6 address/);
    expect(() => classifyTarget("https://github.com/facebook/react/tree/main")).toThrow(
      /Not a GitHub repository URL/,
    );
    expect(() => classifyTarget("http://github.com/facebook/react")).toThrow(
      /Not a GitHub repository URL/,
    );
    expect(() => classifyTarget("file:///etc")).toThrow(/Not a network target/);
  });
});

describe("option validators", () => {
  it("accepts integers in range, as numbers or decimal strings", () => {
    expect(parsePort("8443")).toBe(8443);
    expect(parsePort(443)).toBe(443);
    expect(parseTimeoutMs("5000")).toBe(5000);
    expect(parseCrqcYear("2035")).toBe(2035);
    expect(parseCrqcYear(2040)).toBe(2040);
  });

  it("rejects everything else with a message naming the option", () => {
    for (const bad of ["0", "65536", "abc", "1e3", "", "-1", 80.5, Number.NaN]) {
      expect(() => parsePort(bad, "--port"), String(bad)).toThrow(
        /--port must be an integer from 1 to 65535/,
      );
    }
    for (const bad of ["0", "-5", "abc", 600_001]) {
      expect(() => parseTimeoutMs(bad, "--timeout"), String(bad)).toThrow(
        /--timeout must be an integer/,
      );
    }
    for (const bad of ["abc", "1990", 2101, 2035.5, "NaN"]) {
      expect(() => parseCrqcYear(bad, "--crqc-year"), String(bad)).toThrow(
        /--crqc-year must be an integer from 2020 to 2100/,
      );
    }
  });
});

describe("scanTarget", () => {
  let repoDir: string;
  beforeAll(async () => {
    repoDir = await mkdtemp(join(tmpdir(), "csw-orchestrate-"));
    await writeFile(
      join(repoDir, "package.json"),
      JSON.stringify({ dependencies: { "node-rsa": "1.1.1" } }),
      "utf8",
    );
  });
  afterAll(async () => {
    await rm(repoDir, { recursive: true, force: true });
  });
  beforeEach(() => {
    clone.mockClear();
  });

  it("errors on a missing local path instead of cloning it from GitHub", async () => {
    await expect(scanTarget("./does-not-exist")).rejects.toThrow(
      /No such directory: \.\/does-not-exist/,
    );
    expect(clone).not.toHaveBeenCalled();
  });

  it("refuses non-GitHub remotes before any network I/O", async () => {
    for (const target of [
      "https://127.0.0.1/internal/secret.git",
      "https://localhost/team/secret.git",
      "git@127.0.0.1:internal/secret.git",
      "https://internal.corp.local/team/repo.git",
    ]) {
      await expect(scanTarget(target), target).rejects.toThrow(/only public GitHub repositories/);
    }
  });

  it("applies the SSRF guard to git remotes even with the opt-in", async () => {
    await expect(
      scanTarget("https://127.0.0.1/internal/secret.git", { allowAnyGitHost: true }),
    ).rejects.toThrow(/non-public address/);
  });

  it("clones GitHub targets through the hardened clone and always cleans up", async () => {
    const cleanup = vi.fn(async () => undefined);
    clone.mockResolvedValueOnce({ dir: repoDir, cleanup });
    const findings = await scanTarget("octocat/Hello-World");
    expect(findings.some((f) => f.evidence.includes("node-rsa"))).toBe(true);
    expect(clone).toHaveBeenCalledWith("https://github.com/octocat/Hello-World.git", {
      allowAnyHost: false,
      allowPrivate: false,
      signal: undefined,
    });
    expect(cleanup).toHaveBeenCalledTimes(1);

    const controller = new AbortController();
    const cleanupAfterAbort = vi.fn(async () => undefined);
    clone.mockImplementationOnce(async () => {
      controller.abort();
      return { dir: repoDir, cleanup: cleanupAfterAbort };
    });
    await expect(scanTarget("octocat/Hello-World", { signal: controller.signal })).rejects.toThrow(
      /abort/i,
    );
    expect(cleanupAfterAbort).toHaveBeenCalledTimes(1);
  });

  it("passes the git-host opt-in through for other remotes", async () => {
    clone.mockResolvedValueOnce({ dir: repoDir, cleanup: async () => undefined });
    await scanTarget("https://git.example.com/team/repo.git", {
      allowAnyGitHost: true,
      allowPrivate: true,
    });
    expect(clone).toHaveBeenCalledWith("https://git.example.com/team/repo.git", {
      allowAnyHost: true,
      allowPrivate: true,
      signal: undefined,
    });
  });

  it("guards host targets, including non-canonical numeric spellings of loopback", async () => {
    await expect(scanTarget("127.0.0.1")).rejects.toThrow(/non-public/);
    await expect(scanTarget("0177.0.0.1:8443")).rejects.toThrow(/non-public/);
    await expect(scanTarget("[::1]:8443")).rejects.toThrow(/non-public/);
  });

  it("accepts an already-classified target", async () => {
    const findings = await scanTarget({ kind: "path", dir: repoDir });
    expect(findings.some((f) => f.evidence.includes("node-rsa"))).toBe(true);
  });
});
