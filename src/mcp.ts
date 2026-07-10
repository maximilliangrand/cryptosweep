#!/usr/bin/env node
/**
 * cryptosweep MCP server.
 *
 * A minimal Model Context Protocol server over stdio (newline-delimited
 * JSON-RPC 2.0, protocol 2024-11-05) that exposes cryptosweep as a capability to
 * any MCP client — Urfael, Claude Desktop, or otherwise. No new dependency: the
 * whole protocol is a handful of methods, implemented by hand.
 *
 * Tools:
 *   - scan(target, dataClass?, crqcYear?, advisories?, allowPrivate?)
 *   - data_classes()
 *
 * Everything except JSON-RPC frames goes to stderr; stdout is protocol-only.
 */
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { buildReport } from "./report";
import type { Report } from "./report";
import { scanTarget } from "./orchestrate";
import { assessRisk } from "./model/risk";
import type { RiskModel } from "./model/risk";
import { DATA_CLASSES, defaultProfile, isDataClassId } from "./model/estate";
import { VERSION } from "./version";

const PROTOCOL_VERSION = "2024-11-05";

const TOOLS = [
  {
    name: "scan",
    description:
      "Scan a target for quantum-vulnerable cryptography and return an inventory plus a harvest-now-decrypt-later risk assessment. Target is a hostname/URL (TLS posture), a GitHub owner/repo or URL (cloned + scanned), or a local directory path (source + dependency manifests).",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "hostname/URL, owner/repo, or local directory path" },
        dataClass: {
          type: "string",
          description: `confidentiality class for the risk model: ${DATA_CLASSES.map((c) => c.id).join(", ")}`,
        },
        crqcYear: { type: "integer", description: "assumed year a quantum computer can break current crypto (default 2035)" },
        advisories: { type: "boolean", description: "cross-reference flagged deps against OSV.dev for known CVEs (network)" },
        allowPrivate: { type: "boolean", description: "allow scanning non-public hosts (localhost / RFC 1918)" },
      },
      required: ["target"],
    },
  },
  {
    name: "data_classes",
    description: "List the confidentiality data classes (and their secrecy horizons) available for the risk model.",
    inputSchema: { type: "object", properties: {} },
  },
];

interface JsonRpcMessage {
  jsonrpc?: string;
  id?: number | string | null;
  method?: string;
  params?: Record<string, unknown>;
}

function send(message: Record<string, unknown>): void {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

function reply(id: JsonRpcMessage["id"], result: Record<string, unknown>): Record<string, unknown> {
  return { jsonrpc: "2.0", id, result };
}

function textContent(text: string, isError = false): Record<string, unknown> {
  return { content: [{ type: "text", text }], ...(isError ? { isError: true } : {}) };
}

function num(value: unknown): number | undefined {
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

async function callTool(name: string, args: Record<string, unknown>): Promise<string> {
  if (name === "data_classes") {
    return DATA_CLASSES.map((c) => `${c.id}: ${c.label} (${c.horizonYears}-year secrecy horizon)`).join("\n");
  }
  if (name === "scan") {
    const target = String(args.target ?? "").trim();
    if (!target) throw new Error("target is required");
    const dataClass = args.dataClass ? String(args.dataClass) : undefined;
    if (dataClass && !isDataClassId(dataClass)) {
      throw new Error(`dataClass must be one of: ${DATA_CLASSES.map((c) => c.id).join(", ")}`);
    }
    const findings = await scanTarget(target, {
      advisories: Boolean(args.advisories),
      allowPrivate: Boolean(args.allowPrivate),
    });
    const report = buildReport(target, findings);
    const profile = defaultProfile(report.scanned_at, { dataClassId: dataClass, crqcYear: num(args.crqcYear) });
    const risk = assessRisk(target, report.findings, profile);
    return formatScan(report, risk);
  }
  throw new Error(`unknown tool: ${name}`);
}

function formatScan(report: Report, risk: RiskModel): string {
  const s = report.summary;
  const l = risk.ledger;
  const a = risk.assumptions;
  const lines: string[] = [
    `cryptosweep scan of ${report.target}: ${s.findings} finding(s) (critical ${s.critical}, high ${s.high}, medium ${s.medium}, low ${s.low}, info ${s.info}).`,
    ``,
    `Crypto-agility risk (data class ${a.dataClass}, ${a.horizonYears}yr horizon, CRQC assumed ${a.crqcYear}):`,
    `  exposed(HNDL) ${l.exposedAssets}  overdue ${l.overdueAssets}  act-now(classical) ${l.actNowAssets}  on-track ${l.onTrackAssets}  |  ${Math.round(l.exposureRiskYears)} risk-years exposed`,
    `  ${l.headline}`,
  ];
  if (report.findings.length) {
    lines.push(``, `Findings (top ${Math.min(12, report.findings.length)}):`);
    for (const f of report.findings.slice(0, 12)) {
      lines.push(`  [${f.severity}/${f.confidence ?? "medium"}] ${f.title}  (${f.evidence})`);
    }
    if (report.findings.length > 12) lines.push(`  ... and ${report.findings.length - 12} more.`);
  }
  return lines.join("\n");
}

/** Handle one JSON-RPC message; returns the response to send, or null for notifications. */
export async function dispatch(message: JsonRpcMessage): Promise<Record<string, unknown> | null> {
  const { id, method, params } = message;
  switch (method) {
    case "initialize":
      return reply(id, {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: { name: "cryptosweep", version: VERSION },
      });
    case "notifications/initialized":
    case "notifications/cancelled":
      return null; // notifications take no response
    case "ping":
      return reply(id, {});
    case "tools/list":
      return reply(id, { tools: TOOLS });
    case "tools/call": {
      const name = String(params?.name ?? "");
      const args = (params?.arguments as Record<string, unknown>) ?? {};
      try {
        return reply(id, textContent(await callTool(name, args)));
      } catch (err) {
        return reply(id, textContent(`cryptosweep error: ${err instanceof Error ? err.message : String(err)}`, true));
      }
    }
    default:
      return id !== undefined && id !== null
        ? { jsonrpc: "2.0", id, error: { code: -32601, message: `method not found: ${method}` } }
        : null;
  }
}

export { callTool, TOOLS };

function main(): void {
  const rl = createInterface({ input: process.stdin });
  let chain: Promise<void> = Promise.resolve();
  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let message: JsonRpcMessage;
    try {
      message = JSON.parse(trimmed) as JsonRpcMessage;
    } catch {
      return; // ignore non-JSON noise; never crash the stream
    }
    chain = chain
      .then(async () => {
        const response = await dispatch(message);
        if (response) send(response);
      })
      .catch(() => undefined);
  });
  rl.on("close", () => process.exit(0));
}

// Run the stdio loop only when executed directly, not when imported by tests.
if (process.argv[1] && process.argv[1] === fileURLToPath(import.meta.url)) main();
