import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { callTool, dispatch, TOOLS } from "../src/mcp";

type Reply = Record<string, unknown> & { result?: Record<string, unknown>; error?: { code: number } };

describe("MCP protocol", () => {
  it("answers initialize with the expected protocol version and server info", async () => {
    const r = (await dispatch({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} })) as Reply;
    expect(r?.result?.protocolVersion).toBe("2024-11-05");
    expect((r?.result?.serverInfo as { name: string }).name).toBe("cryptosweep");
  });

  it("advertises the scan and data_classes tools with input schemas", async () => {
    const r = (await dispatch({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} })) as Reply;
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
  let dir: string;
  let previousRoot: string | undefined;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "csw-mcp-"));
    await writeFile(join(dir, "package.json"), JSON.stringify({ dependencies: { jsonwebtoken: "^9.0.0" } }), "utf8");
    previousRoot = process.env.CRYPTOSWEEP_MCP_ROOT;
    process.env.CRYPTOSWEEP_MCP_ROOT = dir;
  });
  afterAll(async () => {
    if (previousRoot === undefined) delete process.env.CRYPTOSWEEP_MCP_ROOT;
    else process.env.CRYPTOSWEEP_MCP_ROOT = previousRoot;
    await rm(dir, { recursive: true, force: true });
  });

  it("scans a local directory and returns findings plus the risk model", async () => {
    const text = await callTool("scan", { target: dir, dataClass: "legal-privileged" });
    expect(text).toContain("jsonwebtoken");
    expect(text).toContain("Crypto-agility risk");
    expect(text).toMatch(/data class Legal \/ privileged/);
  });

  it("rejects an invalid data class", async () => {
    await expect(callTool("scan", { target: dir, dataClass: "nonsense" })).rejects.toThrow(/dataClass must be one of/);
  });

  it("refuses a filesystem target outside the configured root", async () => {
    await expect(callTool("scan", { target: join(dir, "..") })).rejects.toThrow(/must be inside/);
    await expect(callTool("scan", { target: homedir() })).rejects.toThrow(/must be inside/);
  });

  it("does not expose an SSRF escape hatch through the tool schema", async () => {
    const schema = TOOLS.find((t) => t.name === "scan")?.inputSchema as { properties: Record<string, unknown> };
    expect(Object.keys(schema.properties)).not.toContain("allowPrivate");
    // Even if a client sends it anyway, the guard still refuses loopback.
    await expect(callTool("scan", { target: "127.0.0.1", allowPrivate: true })).rejects.toThrow(/non-public/);
  });
});
