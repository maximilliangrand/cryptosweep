import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { homedir, tmpdir } from "node:os";
import { dirname, join, parse } from "node:path";
import { PassThrough } from "node:stream";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { callTool, dispatch, resolveScanRoot, safeLine, serve, TOOLS } from "../src/mcp-server";
import type { JsonRpcMessage } from "../src/mcp-server";

type Reply = Record<string, unknown> & {
  id?: unknown;
  result?: Record<string, unknown>;
  error?: { code: number };
};

const PEM_KEY = `-----BEGIN RSA PRIVATE KEY-----\n${"MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu".repeat(2)}\n-----END RSA PRIVATE KEY-----\n`;

/** Run `fn` with environment overrides, restoring the previous values afterwards. */
async function withEnv<T>(
  overrides: Record<string, string | undefined>,
  fn: () => Promise<T>,
): Promise<T> {
  const previous = Object.fromEntries(Object.keys(overrides).map((key) => [key, process.env[key]]));
  const apply = (values: Record<string, string | undefined>): void => {
    for (const [key, value] of Object.entries(values)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  };
  apply(overrides);
  try {
    return await fn();
  } finally {
    apply(previous);
  }
}

describe("MCP protocol", () => {
  it("answers initialize with the expected protocol version and server info", async () => {
    const r = (await dispatch({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {},
    })) as Reply;
    expect(r?.result?.protocolVersion).toBe("2024-11-05");
    expect((r?.result?.serverInfo as { name: string }).name).toBe("cryptosweep");
  });

  it("advertises the scan and data_classes tools with input schemas", async () => {
    const r = (await dispatch({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
      params: {},
    })) as Reply;
    const tools = r?.result?.tools as Array<{ name: string; inputSchema: unknown }>;
    expect(tools.map((t) => t.name).sort()).toEqual(["data_classes", "scan"]);
    expect(TOOLS.find((t) => t.name === "scan")?.inputSchema).toBeDefined();
  });

  it("treats notifications as fire-and-forget (no response)", async () => {
    expect(await dispatch({ jsonrpc: "2.0", method: "notifications/initialized" })).toBeNull();
  });

  it("returns a JSON-RPC error for an unknown method", async () => {
    const r = (await dispatch({ jsonrpc: "2.0", id: 9, method: "does/not/exist" })) as Reply;
    expect(r?.error?.code).toBe(-32601);
  });

  it("lists data classes via tools/call", async () => {
    const r = (await dispatch({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "data_classes", arguments: {} },
    })) as Reply;
    const text = (r?.result?.content as Array<{ text: string }>)[0]?.text ?? "";
    expect(text).toContain("legal-privileged");
    expect(text).toMatch(/30-year secrecy horizon/);
  });
});

describe("MCP scan tool", () => {
  let base: string;
  let dir: string;
  let outside: string;
  let previousRoot: string | undefined;
  beforeAll(async () => {
    base = await mkdtemp(join(tmpdir(), "csw-mcp-"));
    dir = join(base, "root");
    outside = join(base, "outside");
    await mkdir(dir);
    await mkdir(join(outside, ".ssh"), { recursive: true });
    await writeFile(
      join(dir, "package.json"),
      JSON.stringify({ dependencies: { jsonwebtoken: "^9.0.0" } }),
      "utf8",
    );
    await mkdir(join(dir, "pinned"));
    await writeFile(
      join(dir, "pinned", "package.json"),
      JSON.stringify({ dependencies: { "node-rsa": "1.1.1" } }),
      "utf8",
    );
    await writeFile(
      join(outside, "package.json"),
      JSON.stringify({ dependencies: { "node-rsa": "1.1.1" } }),
      "utf8",
    );
    await writeFile(join(outside, ".ssh", "id_backup.txt"), PEM_KEY, "utf8");
    // A planted symlink inside the root that points out of it.
    await symlink(outside, join(dir, "link"), "dir");
    previousRoot = process.env.CRYPTOSWEEP_MCP_ROOT;
    process.env.CRYPTOSWEEP_MCP_ROOT = dir;
  });
  afterAll(async () => {
    if (previousRoot === undefined) delete process.env.CRYPTOSWEEP_MCP_ROOT;
    else process.env.CRYPTOSWEEP_MCP_ROOT = previousRoot;
    await rm(base, { recursive: true, force: true });
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("scans a local directory and returns findings plus the risk model", async () => {
    const text = await callTool("scan", { target: dir, dataClass: "legal-privileged" });
    expect(text).toContain("jsonwebtoken");
    expect(text).toContain("Crypto-agility risk");
    expect(text).toMatch(/data class Legal \/ privileged/);
  });

  it("applies a migration time and reports coverage, and scopes an empty result", async () => {
    const withYears = await callTool("scan", { target: "pinned", migrationYears: 2 });
    expect(withYears).toMatch(/Coverage:\n {2}source: .*\(complete\)\n {2}deps: .*\(complete\)/);
    await expect(callTool("scan", { target: "pinned", migrationYears: 0 })).rejects.toThrow(/migrationYears must be a number of years/);
    await mkdir(join(dir, "empty"), { recursive: true });
    const empty = await callTool("scan", { target: "empty" });
    expect(empty).toContain("No findings from the checks that ran.");
    expect(empty).toContain("Only the constructs these checks detect were examined");
  });

  it("resolves relative filesystem targets against the root", async () => {
    const text = await callTool("scan", { target: "pinned" });
    expect(text).toContain("node-rsa");
  });

  it("rejects an invalid data class and an invalid CRQC year", async () => {
    await expect(callTool("scan", { target: dir, dataClass: "nonsense" })).rejects.toThrow(
      /dataClass must be one of/,
    );
    await expect(callTool("scan", { target: dir, crqcYear: 1990 })).rejects.toThrow(
      /crqcYear must be an integer/,
    );
    await expect(callTool("scan", { target: dir, crqcYear: "soon" })).rejects.toThrow(
      /crqcYear must be an integer/,
    );
  });

  it("refuses a filesystem target outside the configured root", async () => {
    await expect(callTool("scan", { target: join(dir, "..") })).rejects.toThrow(/must be inside/);
    await expect(callTool("scan", { target: homedir() })).rejects.toThrow(/must be inside/);
    await expect(callTool("scan", { target: "../outside" })).rejects.toThrow(/must be inside/);
    await expect(callTool("scan", { target: "~/.ssh" })).rejects.toThrow(/must be inside/);
  });

  it("refuses a symlink inside the root that escapes it", async () => {
    await expect(callTool("scan", { target: "link" })).rejects.toThrow(/must be inside/);
    await expect(callTool("scan", { target: join(dir, "link") })).rejects.toThrow(/must be inside/);
    await expect(callTool("scan", { target: join(dir, "link", ".ssh") })).rejects.toThrow(
      /must be inside/,
    );
  });

  it("does not expose an SSRF escape hatch through the tool schema", async () => {
    const schema = TOOLS.find((t) => t.name === "scan")?.inputSchema as {
      properties: Record<string, unknown>;
    };
    expect(Object.keys(schema.properties)).not.toContain("allowPrivate");
    expect(Object.keys(schema.properties)).not.toContain("advisories");
    // Even if a client sends it anyway, the guard still refuses loopback.
    await expect(callTool("scan", { target: "127.0.0.1", allowPrivate: true })).rejects.toThrow(
      /non-public/,
    );
  });

  it("refuses git@ remotes and non-GitHub hosts", async () => {
    await expect(callTool("scan", { target: "git@127.0.0.1:internal/secret.git" })).rejects.toThrow(
      /only public GitHub repositories/,
    );
    await expect(
      callTool("scan", { target: "https://127.0.0.1/internal/secret.git" }),
    ).rejects.toThrow(/only public GitHub repositories/);
  });

  it("lets only the operator's launch config switch the SSRF guard off", async () => {
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 1;
    await new Promise<void>((resolve) => server.close(() => resolve()));

    const outcome = await withEnv({ CRYPTOSWEEP_MCP_ALLOW_PRIVATE: "1" }, () =>
      callTool("scan", { target: `127.0.0.1:${port}` }).then(
        (text) => text,
        (err: unknown) => (err instanceof Error ? err.message : String(err)),
      ),
    );
    expect(outcome).not.toMatch(/non-public/);
    await withEnv({ CRYPTOSWEEP_MCP_ALLOW_PRIVATE: "yes please" }, async () => {
      await expect(callTool("scan", { target: `127.0.0.1:${port}` })).rejects.toThrow(/non-public/);
    });
  });

  it("never lets the agent switch on OSV egress; only the operator can", async () => {
    const osv = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ results: [{ vulns: [] }] }),
    }));
    vi.stubGlobal("fetch", osv);
    await callTool("scan", { target: "pinned", advisories: true });
    await callTool("scan", { target: "pinned", advisories: "false" });
    expect(osv).not.toHaveBeenCalled();

    await withEnv({ CRYPTOSWEEP_MCP_ADVISORIES: "1" }, () =>
      callTool("scan", { target: "pinned" }),
    );
    expect(osv).toHaveBeenCalledTimes(1);
  });

  it("strips control characters from untrusted file names before they reach the model", async () => {
    const hostile = join(base, "hostile");
    await mkdir(hostile);
    const name = "a\u001b]0;PWNED\u0007\u001b[31mRED\u001b[0m\n  FORGED LINE\u202e.key";
    await writeFile(join(hostile, name), PEM_KEY, "utf8");
    const text = await withEnv({ CRYPTOSWEEP_MCP_ROOT: base }, () =>
      callTool("scan", { target: "hostile" }),
    );
    expect(text).toContain("PWNED");
    for (const control of ["\u001b", "\u0007", "\u202e"]) expect(text).not.toContain(control);
    expect(text.split("\n").some((line) => line.startsWith("  FORGED LINE"))).toBe(false);
  });

  it("reports errors as text without control characters", async () => {
    const r = (await dispatch({
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "scan", arguments: { target: "./nope\u001b[2J" } },
    })) as Reply;
    const text = (r?.result?.content as Array<{ text: string }>)[0]?.text ?? "";
    expect(r?.result?.isError).toBe(true);
    expect(text).not.toContain("\u001b");
  });
});

describe("resolveScanRoot", () => {
  let base: string;
  beforeAll(async () => {
    base = await realpath(await mkdtemp(join(tmpdir(), "csw-mcp-root-")));
  });
  afterAll(async () => {
    await rm(base, { recursive: true, force: true });
  });

  it("uses an explicitly configured root, resolved to its real path", async () => {
    await symlink(base, join(base, "..", `${parse(base).base}-alias`), "dir");
    const alias = join(dirname(base), `${parse(base).base}-alias`);
    try {
      expect(resolveScanRoot({ CRYPTOSWEEP_MCP_ROOT: alias }, "/")).toEqual({
        root: base,
        rootAlias: alias,
      });
    } finally {
      await rm(alias, { force: true });
    }
  });

  it("allows an operator to configure a broad root on purpose", () => {
    expect(resolveScanRoot({ CRYPTOSWEEP_MCP_ROOT: "/" }, base).root).toBe("/");
  });

  it("refuses a filesystem root, the home directory or an ancestor of it as the implicit default", () => {
    for (const cwd of [parse(base).root, homedir(), dirname(homedir())]) {
      const result = resolveScanRoot({}, cwd);
      expect(result.root, cwd).toBeNull();
      expect(result.rootProblem, cwd).toMatch(/too broad.*CRYPTOSWEEP_MCP_ROOT/);
    }
  });

  it("uses a narrow working directory as the implicit default", () => {
    expect(resolveScanRoot({}, base)).toEqual({ root: base, rootAlias: base });
  });

  it("reports a configured root that does not exist", () => {
    expect(resolveScanRoot({ CRYPTOSWEEP_MCP_ROOT: join(base, "missing") }, "/")).toEqual({
      root: null,
      rootProblem: `the scan root ${join(base, "missing")} does not exist`,
    });
  });

  it("refuses filesystem scans when the implicit root is too broad", async () => {
    const spy = vi.spyOn(process, "cwd").mockReturnValue(parse(base).root);
    try {
      await withEnv({ CRYPTOSWEEP_MCP_ROOT: undefined }, async () => {
        await expect(callTool("scan", { target: base })).rejects.toThrow(
          /too broad to scan by default/,
        );
      });
    } finally {
      spy.mockRestore();
    }
  });
});

describe("safeLine", () => {
  it("replaces C0, C1, separator and bidi control characters, keeping ordinary Unicode", () => {
    expect(safeLine("a\u001b[31mb\u0007c\u009bd\u2028e\u202ef\u2066g\t\u00e5\u00e9\u4e2d")).toBe(
      "a\ufffd[31mb\ufffdc\ufffdd\ufffde\ufffdf\ufffdg \u00e5\u00e9\u4e2d",
    );
  });
});

/** Drive `serve()` over in-memory streams and collect every response it writes. */
function harness(options: Parameters<typeof serve>[2] = {}) {
  const input = new PassThrough();
  const output = new PassThrough();
  const responses: Reply[] = [];
  let buffered = "";
  output.on("data", (chunk: Buffer) => {
    buffered += chunk.toString("utf8");
    const lines = buffered.split("\n");
    buffered = lines.pop() ?? "";
    for (const line of lines) if (line) responses.push(JSON.parse(line) as Reply);
  });
  const done = serve(input, output, options);
  const send = (message: unknown): void => {
    input.write(`${typeof message === "string" ? message : JSON.stringify(message)}\n`);
  };
  return { input, responses, done, send };
}

interface Deferred {
  message: JsonRpcMessage;
  signal: AbortSignal;
  finish: () => void;
}

/** A handler whose tool calls stay pending until the test finishes them. */
function controllableHandler() {
  const calls: Deferred[] = [];
  const handle = (message: JsonRpcMessage, signal: AbortSignal) => {
    if (message.method !== "tools/call") return dispatch(message);
    return new Promise<Record<string, unknown> | null>((resolve) => {
      calls.push({
        message,
        signal,
        finish: () => resolve({ jsonrpc: "2.0", id: message.id, result: { content: [] } }),
      });
    });
  };
  return { calls, handle };
}

const toolCall = (id: number | string) => ({
  jsonrpc: "2.0",
  id,
  method: "tools/call",
  params: { name: "scan", arguments: { target: "x" } },
});

describe("MCP stdio lifecycle", () => {
  it("finishes and flushes an in-flight tool call after stdin closes", async () => {
    const { calls, handle } = controllableHandler();
    const { input, responses, done, send } = harness({ handle });
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    send(toolCall(2));
    input.end();
    await vi.waitFor(() => expect(calls).toHaveLength(1));

    let drained = false;
    void done.then(() => {
      drained = true;
    });
    await new Promise((resolve) => setImmediate(resolve));
    expect(drained).toBe(false);

    calls[0]?.finish();
    await done;
    expect(responses.map((r) => r.id).sort()).toEqual([1, 2]);
  });

  it("runs the real dispatcher end to end", async () => {
    const { input, responses, done, send } = harness();
    send({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "data_classes", arguments: {} },
    });
    input.end();
    await done;
    expect(JSON.stringify(responses[0]?.result)).toContain("legal-privileged");
  });

  it("bounds concurrency and answers busy when the queue is full", async () => {
    const { calls, handle } = controllableHandler();
    const { input, responses, done, send } = harness({ handle, maxConcurrent: 1, maxQueued: 1 });
    send(toolCall(1));
    send(toolCall(2));
    send(toolCall(3));
    await vi.waitFor(() => expect(responses.some((r) => r.id === 3)).toBe(true));
    expect(responses.find((r) => r.id === 3)?.error?.code).toBe(-32000);
    expect(calls).toHaveLength(1);

    calls[0]?.finish();
    await vi.waitFor(() => expect(calls).toHaveLength(2));
    calls[1]?.finish();
    input.end();
    await done;
    expect(responses.map((r) => r.id).sort()).toEqual([1, 2, 3]);
  });

  it("stays responsive to ping while a tool call runs", async () => {
    const { calls, handle } = controllableHandler();
    const { input, responses, done, send } = harness({ handle });
    send(toolCall(1));
    send({ jsonrpc: "2.0", id: 2, method: "ping" });
    await vi.waitFor(() => expect(responses.some((r) => r.id === 2)).toBe(true));
    calls[0]?.finish();
    input.end();
    await done;
  });

  it("cancels a running call: the signal aborts and no response is sent", async () => {
    const { calls, handle } = controllableHandler();
    const { input, responses, done, send } = harness({ handle });
    send(toolCall("scan-1"));
    await vi.waitFor(() => expect(calls).toHaveLength(1));
    send({
      jsonrpc: "2.0",
      method: "notifications/cancelled",
      params: { requestId: "scan-1", reason: "user" },
    });
    await vi.waitFor(() => expect(calls[0]?.signal.aborted).toBe(true));
    calls[0]?.finish();
    input.end();
    await done;
    expect(responses).toEqual([]);
  });

  it("cancels a queued call before it starts", async () => {
    const { calls, handle } = controllableHandler();
    const { input, responses, done, send } = harness({ handle, maxConcurrent: 1 });
    send(toolCall(1));
    send(toolCall(2));
    await vi.waitFor(() => expect(calls).toHaveLength(1));
    send({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 2 } });
    send({ jsonrpc: "2.0", id: 3, method: "ping" });
    await vi.waitFor(() => expect(responses.some((r) => r.id === 3)).toBe(true));
    calls[0]?.finish();
    input.end();
    await done;
    expect(calls).toHaveLength(1);
    expect(responses.map((r) => r.id).sort()).toEqual([1, 3]);
  });

  it("answers malformed input per JSON-RPC instead of dropping it", async () => {
    const { calls, handle } = controllableHandler();
    const { input, responses, done, send } = harness({ handle });
    send("{not json");
    send("[1,2]");
    send({ jsonrpc: "2.0", id: 5, result: {} });
    send({
      jsonrpc: "2.0",
      method: "tools/call",
      params: { name: "scan", arguments: { target: "x" } },
    });
    send(toolCall(6));
    send(toolCall(6));
    send({ jsonrpc: "2.0", id: 7, method: "ping" });
    await vi.waitFor(() => expect(responses.some((r) => r.id === 7)).toBe(true));
    calls[0]?.finish();
    input.end();
    await done;
    expect(responses.find((r) => r.error?.code === -32700)?.id).toBeNull();
    expect(responses.filter((r) => r.error?.code === -32600).map((r) => r.id)).toEqual([
      null,
      5,
      6,
    ]);
    // A tool call without an id is never run.
    expect(calls).toHaveLength(1);
  });
});
