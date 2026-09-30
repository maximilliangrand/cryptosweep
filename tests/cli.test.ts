import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/**
 * The CLI, built from source and run as a process: option validation has to
 * happen before any scan, network request or output file, and that ordering is
 * only observable from outside.
 */

const repoRoot = fileURLToPath(new URL("..", import.meta.url));

/** Preloaded into the CLI: replaces fetch so an OSV lookup is visible on stderr and never leaves the machine. */
const FETCH_STUB = `globalThis.fetch = async () => {
  process.stderr.write("OSV-REQUEST\\n");
  return { ok: true, status: 200, json: async () => ({ results: [{ vulns: [] }] }) };
};
`;

interface CliResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

describe("cryptosweep CLI", () => {
  let work: string;
  let cli: string;
  let preload: string;
  let project: string;

  const run = (args: string[], cwd = work): Promise<CliResult> =>
    new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ["--import", preload, cli, ...args], {
        cwd,
        env: { ...process.env, NO_COLOR: "1" },
        stdio: ["ignore", "pipe", "pipe"],
      });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (chunk: Buffer) => {
        stdout += chunk.toString("utf8");
      });
      child.stderr.on("data", (chunk: Buffer) => {
        stderr += chunk.toString("utf8");
      });
      child.on("error", reject);
      child.on("close", (code) => resolve({ code, stdout, stderr }));
    });

  beforeAll(async () => {
    work = await realpath(await mkdtemp(join(tmpdir(), "csw-cli-")));
    cli = join(work, "cli.mjs");
    await build({
      entryPoints: [join(repoRoot, "src", "cli.ts")],
      outfile: cli,
      bundle: true,
      platform: "node",
      format: "esm",
      target: "node20",
      logLevel: "silent",
    });
    preload = join(work, "fetch-stub.mjs");
    await writeFile(preload, FETCH_STUB, "utf8");
    project = join(work, "project");
    await mkdir(project);
    await writeFile(
      join(project, "package.json"),
      JSON.stringify({ dependencies: { "node-rsa": "1.1.1" } }),
      "utf8",
    );
  }, 60_000);

  afterAll(async () => {
    await rm(work, { recursive: true, force: true });
  });

  it.each([
    [["--crqc-year", "abc"], /--crqc-year must be an integer from 2020 to 2100 \(got "abc"\)/],
    [["--crqc-year", "1990"], /--crqc-year must be an integer from 2020 to 2100/],
    [["--fail-on", "bogus"], /--fail-on must be one of/],
    [["--data-class", "nope"], /--data-class must be one of/],
    [["--port", "8443"], /--port applies only to hostname\/URL \(TLS\) targets/],
    [["--timeout", "5000"], /--timeout applies only to hostname\/URL \(TLS\) targets/],
    [["--md", "same.out"], /--out and --md would both write same\.out/],
  ])("rejects %j before scanning or writing any output", async (flags, message) => {
    const out = join(work, "same.out");
    const result = await run(["scan", project, "--out", out, ...flags]);
    expect(result.code).toBe(1);
    expect(result.stderr).toMatch(message);
    expect(existsSync(out)).toBe(false);
    expect(result.stdout).toBe("");
  });

  it.each([
    [["--port", "0"], /--port must be an integer from 1 to 65535/],
    [["--port", "70000"], /--port must be an integer from 1 to 65535/],
    [["--port", "abc"], /--port must be an integer from 1 to 65535/],
    [["--timeout", "0"], /--timeout must be an integer from 1 to 600000/],
    [["--timeout", "soon"], /--timeout must be an integer/],
    [["--advisories"], /--advisories applies only to repository and directory targets/],
  ])("rejects %j for a host target before any network I/O", async (flags, message) => {
    // A documentation address: nothing answers there even if validation were skipped.
    const result = await run(["scan", "192.0.2.1", ...flags]);
    expect(result.code).toBe(1);
    expect(result.stderr).toMatch(message);
  });

  it("refuses a missing local path instead of cloning it from GitHub", async () => {
    const result = await run(["scan", "./does-not-exist"]);
    expect(result.code).toBe(1);
    expect(result.stderr).toMatch(/No such directory: \.\/does-not-exist/);
    expect(result.stderr).not.toMatch(/git clone/);
  });

  it("refuses git@ and non-GitHub remotes unless --allow-any-git-host is given", async () => {
    for (const target of [
      "git@127.0.0.1:internal/secret.git",
      "https://127.0.0.1/internal/secret.git",
    ]) {
      const result = await run(["scan", target]);
      expect(result.code, target).toBe(1);
      expect(result.stderr, target).toMatch(
        /only public GitHub repositories.*--allow-any-git-host/,
      );
    }
    // The opt-in widens the host list; the SSRF guard still applies.
    const optIn = await run([
      "scan",
      "https://127.0.0.1/internal/secret.git",
      "--allow-any-git-host",
    ]);
    expect(optIn.code).toBe(1);
    expect(optIn.stderr).toMatch(/non-public address/);
  });

  it("prints the OSV disclosure before any dependency data is sent", async () => {
    const result = await run([
      "scan",
      project,
      "--advisories",
      "--out",
      join(work, "advisories.json"),
    ]);
    expect(result.code).toBe(0);
    const notice = result.stderr.indexOf("--advisories posts flagged");
    const request = result.stderr.indexOf("OSV-REQUEST");
    expect(notice).toBeGreaterThanOrEqual(0);
    expect(request).toBeGreaterThan(notice);
  });

  it("writes a numeric --out value to a file of that name, not to a file descriptor", async () => {
    const dir = await mkdtemp(join(work, "numeric-"));
    const result = await run(["scan", project, "--out", "1"], dir);
    expect(result.code).toBe(0);
    expect(result.stdout).toMatch(/^Scanned /);
    expect(JSON.parse(readFileSync(join(dir, "1"), "utf8"))).toMatchObject({ target: project });
  });

  it("runs a valid scan and applies the validated options", async () => {
    const riskFile = join(work, "risk.json");
    const result = await run([
      "scan",
      project,
      "--crqc-year",
      "2040",
      "--data-class",
      "legal-privileged",
      "--risk",
      riskFile,
    ]);
    expect(result.code).toBe(0);
    expect(result.stderr).toMatch(/CRQC assumed 2040/);
    expect(JSON.parse(readFileSync(riskFile, "utf8"))).toMatchObject({
      assumptions: { crqcYear: 2040 },
    });
  });
});
