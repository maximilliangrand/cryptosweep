import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { chmod, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import type { Options } from "tsup";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import tsupConfig from "../tsup.config";

/**
 * The cryptosweep-mcp bin, built and launched the way package managers launch
 * it: through a relative symlink in node_modules/.bin, and through a symlinked
 * directory (macOS /tmp is one). The bin used to compare process.argv[1] with
 * import.meta.url, which differ across a symlink, and exit silently.
 */

const repoRoot = fileURLToPath(new URL("..", import.meta.url));

interface RunResult {
  code: number | null;
  responses: Array<{ id?: unknown; result?: Record<string, unknown>; error?: unknown }>;
  stderr: string;
}

function runServer(
  command: string,
  args: string[],
  lines: unknown[],
  env: NodeJS.ProcessEnv,
): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", reject);
    child.on("close", (code) => {
      const responses = stdout
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line) as RunResult["responses"][number]);
      resolve({ code, responses, stderr });
    });
    // Write every request and close stdin at once: the server must still answer
    // all of them, including the scan that is in flight when stdin ends.
    child.stdin.end(lines.map((line) => `${JSON.stringify(line)}\n`).join(""));
  });
}

describe("cryptosweep-mcp bin", () => {
  let work: string;
  let target: string;
  let shim: string;
  let aliasedBin: string;

  beforeAll(async () => {
    work = await realpath(await mkdtemp(join(tmpdir(), "csw-mcp-bin-")));
    const dist = join(work, "node_modules", "cryptosweep", "dist");
    await build({
      entryPoints: [join(repoRoot, "src", "mcp.ts")],
      outfile: join(dist, "mcp.js"),
      bundle: true,
      platform: "node",
      format: "esm",
      target: "node20",
      logLevel: "silent",
    });
    await writeFile(join(dist, "..", "package.json"), JSON.stringify({ type: "module" }), "utf8");
    await chmod(join(dist, "mcp.js"), 0o755);

    const binDir = join(work, "node_modules", ".bin");
    await mkdir(binDir, { recursive: true });
    shim = join(binDir, "cryptosweep-mcp");
    await symlink("../cryptosweep/dist/mcp.js", shim);

    await symlink(work, `${work}-alias`, "dir");
    aliasedBin = join(`${work}-alias`, "node_modules", "cryptosweep", "dist", "mcp.js");

    target = join(work, "project");
    await mkdir(target);
    await writeFile(
      join(target, "package.json"),
      JSON.stringify({ dependencies: { "node-rsa": "1.1.1" } }),
      "utf8",
    );
  }, 60_000);

  afterAll(async () => {
    await rm(`${work}-alias`, { force: true });
    await rm(work, { recursive: true, force: true });
  });

  const requests = (): unknown[] => [
    { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
    {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "scan", arguments: { target: "project" } },
    },
  ];

  const launches: Array<[string, () => [string, string[]]]> = [
    ["node through the node_modules/.bin symlink", () => [process.execPath, [shim]]],
    ["node through a symlinked directory", () => [process.execPath, [aliasedBin]]],
  ];
  if (process.platform !== "win32") {
    launches.push(["the shebang through the node_modules/.bin symlink", () => [shim, []]]);
  }

  it.each(launches)(
    "completes an initialize round-trip and a scan when launched via %s",
    async (_, launch) => {
      const [command, args] = launch();
      const result = await runServer(command, args, requests(), {
        ...process.env,
        CRYPTOSWEEP_MCP_ROOT: work,
      });
      expect(result.stderr).toBe("");
      expect(result.code).toBe(0);
      const init = result.responses.find((r) => r.id === 1);
      expect(init?.result?.protocolVersion).toBe("2024-11-05");
      const scan = result.responses.find((r) => r.id === 2);
      expect(JSON.stringify(scan?.result)).toContain("node-rsa");
    },
  );
});

describe("bin build configuration", () => {
  const configs = (Array.isArray(tsupConfig) ? tsupConfig : [tsupConfig]) as Options[];
  const entries = (config: Options): string[] =>
    Array.isArray(config.entry) ? config.entry : Object.values(config.entry ?? {});

  it("emits the bin entries as ESM only, never as CJS", () => {
    const bins = configs.filter((config) =>
      entries(config).some((e) => /src\/(cli|mcp)\.ts$/.test(e)),
    );
    expect(bins.length).toBeGreaterThan(0);
    for (const config of bins) expect(config.format).toEqual(["esm"]);
  });

  it("points package.json bins at the ESM builds", () => {
    const pkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8")) as {
      bin: Record<string, string>;
    };
    expect(pkg.bin).toEqual({ cryptosweep: "./dist/cli.js", "cryptosweep-mcp": "./dist/mcp.js" });
  });
});
