#!/usr/bin/env node
/**
 * cryptosweep CLI.
 *
 * Subcommands:
 *   scan <target>   scan a hostname/URL (TLS) or a GitHub repo / local dir (source)
 *   email           email a previously-generated JSON report via Resend
 *   version         print the version
 *   help            print usage
 */
import { readFile, writeFile } from "node:fs/promises";
import { existsSync, statSync } from "node:fs";
import { cac } from "cac";
import { buildReport, failsThreshold, toJson, toMarkdown } from "./report";
import type { Finding, Report, Severity } from "./report";
import { toCbom } from "./output/cbom";
import { toSarif } from "./output/sarif";
import { scanTls } from "./scanners/tls";
import { cloneRepo, scanSource } from "./scanners/source";
import { scanDeps } from "./scanners/deps";
import { renderHtml, renderText } from "./email/render";
import { sendEmail } from "./email/resend";
import { VERSION } from "./version";

interface ScanOptions {
  out?: string;
  md?: string;
  cbom?: string;
  sarif?: string;
  failOn?: string;
  port?: string | number;
  timeout?: string | number;
}

const SEVERITIES: ReadonlySet<string> = new Set(["critical", "high", "medium", "low", "info"]);

type Target =
  | { kind: "github"; url: string }
  | { kind: "host"; host: string; port: number }
  | { kind: "path"; dir: string };

const stdout = (text: string): void => void process.stdout.write(text);
const stderr = (text: string): void => void process.stderr.write(text);

function classifyTarget(target: string): Target {
  if (existsSync(target) && statSync(target).isDirectory()) {
    return { kind: "path", dir: target };
  }

  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(target) || target.startsWith("git@");
  if (hasScheme) {
    if (/(^|\/\/|@)github\.com[/:]/i.test(target) || target.endsWith(".git")) {
      return { kind: "github", url: target };
    }
    try {
      const url = new URL(target);
      return { kind: "host", host: url.hostname, port: url.port ? Number(url.port) : 443 };
    } catch {
      /* fall through to bare-host handling */
    }
  }

  if (/^[\w.-]+\/[\w.-]+$/.test(target) && !target.includes("..")) {
    return { kind: "github", url: `https://github.com/${target.replace(/\.git$/, "")}.git` };
  }

  const [host, portStr] = target.split(":");
  return { kind: "host", host: host || target, port: portStr ? Number(portStr) : 443 };
}

async function runScan(target: string, options: ScanOptions): Promise<void> {
  try {
    const parsed = classifyTarget(target);
    const timeoutMs = options.timeout ? Number(options.timeout) : 10_000;
    const findings =
      parsed.kind === "host"
        ? await scanTls(parsed.host, {
            port: options.port ? Number(options.port) : parsed.port,
            timeoutMs,
          })
        : parsed.kind === "path"
          ? await scanLocalDir(parsed.dir)
          : await scanClonedRepo(parsed.url);

    const report = buildReport(target, findings);

    if (options.out) await writeFile(options.out, `${toJson(report)}\n`, "utf8");
    if (options.md) await writeFile(options.md, `${toMarkdown(report)}\n`, "utf8");
    if (options.cbom) await writeFile(options.cbom, `${toCbom(report)}\n`, "utf8");
    if (options.sarif) await writeFile(options.sarif, `${toSarif(report)}\n`, "utf8");

    const wroteFile = Boolean(options.out || options.md || options.cbom || options.sarif);
    if (!wroteFile) {
      stdout(`${toMarkdown(report)}\n`);
    } else {
      const { summary } = report;
      stdout(
        `Scanned ${target}: ${summary.findings} finding(s) ` +
          `(critical ${summary.critical}, high ${summary.high}, medium ${summary.medium}, ` +
          `low ${summary.low}, info ${summary.info}).\n`,
      );
    }

    if (options.failOn) {
      const threshold = options.failOn.toLowerCase();
      if (!SEVERITIES.has(threshold)) {
        throw new Error(`--fail-on must be one of critical|high|medium|low|info (got "${options.failOn}")`);
      }
      if (failsThreshold(report, threshold as Severity)) {
        stderr(`cryptosweep: findings at or above "${threshold}" — failing (exit 2).\n`);
        process.exitCode = 2;
      }
    }
  } catch (err) {
    stderr(`cryptosweep: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  }
}

async function scanLocalDir(dir: string): Promise<Finding[]> {
  const [source, deps] = await Promise.all([scanSource(dir), scanDeps(dir)]);
  return [...source, ...deps];
}

async function scanClonedRepo(url: string): Promise<Finding[]> {
  const repo = await cloneRepo(url);
  try {
    return await scanLocalDir(repo.dir);
  } finally {
    await repo.cleanup();
  }
}

interface EmailOptions {
  report?: string;
  to?: string;
  from?: string;
  subject?: string;
}

const DEFAULT_FROM = "scan@cryptosweep.com";

async function loadReport(path: string): Promise<Report> {
  const raw = await readFile(path, "utf8");
  const parsed = JSON.parse(raw) as unknown;
  if (!parsed || typeof parsed !== "object") throw new Error(`${path}: not a JSON object`);
  const candidate = parsed as Partial<Report>;
  if (typeof candidate.target !== "string" || !Array.isArray(candidate.findings) || !candidate.summary) {
    throw new Error(`${path}: not a cryptosweep report (missing target/findings/summary)`);
  }
  return candidate as Report;
}

async function runEmail(options: EmailOptions): Promise<void> {
  try {
    if (!options.report) throw new Error("--report <file> is required");
    if (!options.to) throw new Error("--to <email> is required");
    const apiKey = process.env.RESEND_API_KEY;
    if (!apiKey) throw new Error("RESEND_API_KEY is not set");
    const from = options.from ?? process.env.SCAN_FROM_EMAIL ?? DEFAULT_FROM;
    const report = await loadReport(options.report);
    const subject = options.subject ?? `cryptosweep PQ readiness report — ${report.target}`;
    const result = await sendEmail({
      apiKey,
      from,
      to: options.to,
      subject,
      html: renderHtml(report),
      text: renderText(report),
    });
    if (result.error || !result.id) {
      throw new Error(result.error ?? "unknown Resend error");
    }
    stdout(`Sent email ${result.id} to ${options.to} (from ${from}).\n`);
  } catch (err) {
    stderr(`cryptosweep: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  }
}

const cli = cac("cryptosweep");

cli
  .command("scan <target>", "Scan a host/URL (TLS posture) or a GitHub repo / local dir (source crypto)")
  .option("--out <file>", "Write the JSON report to <file>")
  .option("--md <file>", "Write the Markdown report to <file>")
  .option("--cbom <file>", "Write a CycloneDX 1.6 CBOM to <file>")
  .option("--sarif <file>", "Write a SARIF 2.1.0 log to <file> (for CI / code scanning)")
  .option("--fail-on <severity>", "Exit non-zero if any finding is at/above this severity")
  .option("--port <port>", "TLS port (defaults to 443 or the port in the target)")
  .option("--timeout <ms>", "TLS handshake timeout in milliseconds (default 10000)")
  .example("  cryptosweep scan https://www.example.com --out report.json --cbom cbom.json")
  .example("  cryptosweep scan facebook/react --sarif results.sarif --fail-on high")
  .action(runScan);

cli
  .command("email", "Email a previously-generated JSON report via Resend")
  .option("--report <file>", "Path to a cryptosweep JSON report")
  .option("--to <email>", "Recipient email address")
  .option("--from <email>", `Sender email (defaults to $SCAN_FROM_EMAIL or ${DEFAULT_FROM})`)
  .option("--subject <subject>", "Email subject (defaults to a per-target line)")
  .example("  cryptosweep email --report /tmp/csw-smoke.json --to lead@example.com")
  .action(runEmail);

cli.command("version", "Print the cryptosweep version").action(() => stdout(`${VERSION}\n`));
cli.command("help", "Print usage").action(() => cli.outputHelp());
cli.command("").action(() => cli.outputHelp());

cli.help();
cli.version(VERSION);

async function main(): Promise<void> {
  cli.parse(process.argv, { run: false });
  await cli.runMatchedCommand();
}

main().catch((err: unknown) => {
  stderr(`cryptosweep: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
});
