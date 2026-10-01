/**
 * Cancellation reaches the work itself. The MCP server's AbortSignal used to be
 * checked only between phases and inside a clone, so a cancelled directory or
 * TLS scan ran to completion (and kept its concurrency slot) with only the
 * response suppressed, and Ctrl-C during a CLI clone left /tmp/cryptosweep-*
 * behind.
 */
import { spawn } from "node:child_process";
import { chmod, mkdir, mkdtemp, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import type { Server, Socket } from "node:net";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { callTool, serve } from "../src/mcp-server";
import type { JsonRpcMessage } from "../src/mcp-server";
import { scanLocalDir } from "../src/orchestrate";
import { scanDeps } from "../src/scanners/deps";
import { scanSource } from "../src/scanners/source";
import { scanTls } from "../src/scanners/tls";

const posix = process.platform !== "win32";
let work: string;

beforeAll(async () => {
  work = await realpath(await mkdtemp(join(tmpdir(), "csw-cancel-")));
  const tree = join(work, "tree");
  for (let d = 0; d < 20; d += 1) {
    await mkdir(join(tree, `d${d}`), { recursive: true });
    for (let f = 0; f < 20; f += 1) await writeFile(join(tree, `d${d}`, `f${f}.js`), 'require("crypto").createHash("md5");\n');
  }
  await writeFile(join(tree, "package.json"), JSON.stringify({ dependencies: { "node-rsa": "1.1.1" } }));
});

afterAll(async () => {
  await rm(work, { recursive: true, force: true });
});

describe("directory scans", () => {
  it("reject once the signal is aborted, instead of walking the tree", async () => {
    const reason = new Error("cancelled by the client");
    const signal = AbortSignal.abort(reason);
    await expect(scanSource(join(work, "tree"), { signal })).rejects.toBe(reason);
    await expect(scanDeps(join(work, "tree"), { signal })).rejects.toBe(reason);
    await expect(scanLocalDir(join(work, "tree"), false, signal)).rejects.toBe(reason);
  });

  it("stop part-way through when aborted during the walk", async () => {
    const controller = new AbortController();
    const walk = scanSource(join(work, "tree"), { signal: controller.signal });
    controller.abort(new Error("stop"));
    await expect(walk).rejects.toThrow("stop");
  });

  it("reach the MCP tool call", async () => {
    const previous = process.env.CRYPTOSWEEP_MCP_ROOT;
    process.env.CRYPTOSWEEP_MCP_ROOT = work;
    try {
      await expect(callTool("scan", { target: "tree" }, AbortSignal.abort(new Error("cancelled")))).rejects.toThrow("cancelled");
    } finally {
      if (previous === undefined) delete process.env.CRYPTOSWEEP_MCP_ROOT;
      else process.env.CRYPTOSWEEP_MCP_ROOT = previous;
    }
  });
});

describe("TLS scans", () => {
  let server: Server;
  let port: number;
  const sockets = new Set<Socket>();

  beforeAll(async () => {
    // Accepts TCP and never answers the ClientHello: every handshake hangs until its timeout.
    server = createServer((socket) => {
      sockets.add(socket);
      socket.resume(); // read (and discard) the ClientHello, so the client's close is seen
      socket.on("close", () => sockets.delete(socket));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    port = typeof address === "object" && address ? address.port : 0;
  });

  afterAll(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("destroy their connections when aborted, long before the handshake timeout", async () => {
    const controller = new AbortController();
    const started = Date.now();
    const scan = scanTls("127.0.0.1", { port, allowPrivate: true, timeoutMs: 20_000, signal: controller.signal });
    setTimeout(() => controller.abort(new Error("cancelled")), 100);
    await expect(scan).rejects.toThrow("cancelled");
    expect(Date.now() - started).toBeLessThan(5_000);
    await expect.poll(() => sockets.size, { timeout: 2_000 }).toBe(0);
  });
});

describe("MCP shutdown", () => {
  it("aborts running calls, drops queued ones and resolves", async () => {
    const signals: AbortSignal[] = [];
    const handle = (message: JsonRpcMessage, signal: AbortSignal): Promise<null> => {
      signals.push(signal);
      return new Promise((resolve) => signal.addEventListener("abort", () => resolve(null), { once: true }));
    };
    const input = new PassThrough();
    const output = new PassThrough();
    const shutdown = new AbortController();
    const done = serve(input, output, { handle, maxConcurrent: 1, signal: shutdown.signal });
    for (const id of [1, 2]) input.write(`${JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "scan" } })}\n`);
    await expect.poll(() => signals.length).toBe(1);
    shutdown.abort();
    await done;
    expect(signals).toHaveLength(1); // the queued call never started
    expect(signals[0]?.aborted).toBe(true);
  });
});

/** A stand-in git whose clone never finishes, so the CLI is mid-clone when interrupted. */
const HANGING_GIT = `#!/usr/bin/env node
const fs = require("fs");
const path = require("path");
const args = process.argv.slice(2);
const dir = args[args.length - 1];
fs.mkdirSync(path.join(dir, ".git", "objects", "pack"), { recursive: true });
fs.writeFileSync(path.join(${JSON.stringify("__READY__")}), "cloning");
setInterval(() => {}, 1000);
`;

describe.skipIf(!posix)("the CLI on SIGINT during a clone", () => {
  let cli: string;
  let bin: string;
  let scratch: string;
  let ready: string;

  beforeAll(async () => {
    cli = join(work, "cli.mjs");
    await build({
      entryPoints: [fileURLToPath(new URL("../src/cli.ts", import.meta.url))],
      outfile: cli,
      bundle: true,
      platform: "node",
      format: "esm",
      target: "node22",
      logLevel: "silent",
    });
    bin = join(work, "bin");
    scratch = join(work, "scratch-tmp");
    ready = join(work, "git-started");
    await mkdir(bin);
    await mkdir(scratch);
    await writeFile(join(bin, "git"), HANGING_GIT.replace("__READY__", ready));
    await chmod(join(bin, "git"), 0o755);
  }, 60_000);

  it("kills git, removes the clone directory and exits 130", async () => {
    // An IP-literal remote: nothing is resolved, and the fake git never touches the network.
    const child = spawn(process.execPath, [cli, "scan", "https://127.0.0.1:9/team/repo.git", "--allow-any-git-host", "--allow-private"], {
      env: { ...process.env, PATH: `${bin}${delimiter}${process.env.PATH ?? ""}`, TMPDIR: scratch },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    const exit = new Promise<number | null>((resolve) => child.on("close", (code) => resolve(code)));
    await expect.poll(async () => (await readdir(work)).includes("git-started"), { timeout: 10_000 }).toBe(true);
    expect(await readdir(scratch)).toHaveLength(1); // the clone's temp directory exists mid-clone
    child.kill("SIGINT");
    expect(await exit).toBe(130);
    expect(stderr).toMatch(/cancelled|interrupted/);
    expect(await readdir(scratch)).toEqual([]);
  }, 30_000);
});
