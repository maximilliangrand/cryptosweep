/**
 * MCP filesystem confinement happens before anything is stat'ed. Classifying
 * the target used to stat `resolve(root, target)` first, so
 * `a/../../../../Users/x/.ssh/id_ed25519` answered "is a file", a missing path
 * answered with a DNS failure for `a`, and an existing directory "must be
 * inside": a model could map files outside the root.
 */
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { callTool, mcpTarget } from "../src/mcp-server";
import type { ServerConfig } from "../src/mcp-server";

let base: string;
let root: string;
let config: ServerConfig;

beforeAll(async () => {
  base = await realpath(await mkdtemp(join(tmpdir(), "csw-mcp-oracle-")));
  root = join(base, "root");
  await mkdir(join(root, "sub"), { recursive: true });
  await writeFile(join(root, "sub", "notes.txt"), "inside\n");
  await mkdir(join(base, "outside", "dir"), { recursive: true });
  await writeFile(join(base, "outside", "id_ed25519"), "secret\n");
  config = { root, rootAlias: root, allowPrivate: false, advisories: false };
});

afterAll(async () => {
  await rm(base, { recursive: true, force: true });
});

/** A target that climbs out of the root through a first segment, so it does not start with `../`. */
function climb(to: string): string {
  return `a/${relative(join(root, "a"), join(base, to))}`;
}

function outcome(target: string): string {
  try {
    return `ok ${JSON.stringify(mcpTarget(target, config))}`;
  } catch (err) {
    return (err instanceof Error ? err.message : String(err)).replace(target, "<target>");
  }
}

describe("MCP targets outside the root", () => {
  it("get one answer whether the path is a file, a directory or missing", () => {
    const answers = [climb("outside/id_ed25519"), climb("outside/dir"), climb("outside/missing")].map(outcome);
    expect(new Set(answers).size).toBe(1);
    expect(answers[0]).toMatch(/filesystem targets must be inside/);
  });

  it("are refused before any DNS lookup", async () => {
    // The old classifier read `a/../../missing` as the host `a` and resolved it.
    await expect(callTool("scan", { target: climb("outside/missing") }, undefined)).rejects.toThrow(/must be inside/);
  });

  it("cannot be probed through a URL-shaped target either", () => {
    const traversal = (to: string): string => `x://${"../".repeat(12)}${join(base, to).slice(1)}`;
    const existing = outcome(traversal("outside/id_ed25519"));
    expect(existing).not.toMatch(/is a file/);
    expect(existing).toBe(outcome(traversal("outside/missing")));
  });

  it("include the home directory, which is not expanded", () => {
    expect(outcome("~/.ssh/id_ed25519")).toMatch(/must be inside/);
    expect(outcome("~/.ssh/id_ed25519")).toBe(outcome("~/missing"));
  });
});

describe("MCP targets inside the root", () => {
  it("are classified as before", () => {
    expect(mcpTarget("sub", config)).toEqual({ kind: "path", dir: join(root, "sub") });
    expect(mcpTarget("./sub", config)).toEqual({ kind: "path", dir: join(root, "sub") });
    expect(outcome("sub/deeper/missing")).toBe("No such directory: <target>");
    // One `/` and valid names: a missing local directory reads as GitHub shorthand, as on the CLI.
    expect(mcpTarget("sub/missing", config)).toMatchObject({ kind: "github", owner: "sub", repo: "missing" });
    expect(outcome("sub/notes.txt")).toBe("<target> is a file; pass the directory that contains it");
  });

  it("still reach GitHub shorthand, URLs and hosts", () => {
    expect(mcpTarget("owner/repo", config)).toMatchObject({ kind: "github", owner: "owner", repo: "repo" });
    expect(mcpTarget("https://example.com:8443/x", config)).toEqual({ kind: "host", host: "example.com", port: 8443 });
    expect(mcpTarget("example.com", config)).toEqual({ kind: "host", host: "example.com", port: 443 });
  });

  it("read a multi-segment non-GitHub path as a path, not a host", () => {
    expect(outcome("example.com/login")).toBe("No such directory: <target>");
  });
});
