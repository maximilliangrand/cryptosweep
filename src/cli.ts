#!/usr/bin/env node
/**
 * cryptosweep CLI.
 *
 * Subcommands:
 *   scan <target>   scan a hostname/URL (TLS) or a GitHub repo / local dir (source)
 *   version         print the version
 *   help            print usage
 */
import { writeFile } from "node:fs/promises";
import { existsSync, statSync } from "node:fs";
import { cac } from "cac";
import { buildReport, toJson, toMarkdown } from "./report";
import { scanTls } from "./scanners/tls";
import { cloneRepo, scanSource } from "./scanners/source";
import { VERSION } from "./version";

interface ScanOptions {
  out?: string;
  md?: string;
  port?: string | number;
  timeout?: string | number;
}

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
          ? await scanSource(parsed.dir)
          : await scanClonedRepo(parsed.url);

    const report = buildReport(target, findings);

    if (options.out) await writeFile(options.out, `${toJson(report)}\n`, "utf8");
    if (options.md) await writeFile(options.md, `${toMarkdown(report)}\n`, "utf8");

    if (!options.out && !options.md) {
      stdout(`${toMarkdown(report)}\n`);
    } else {
      const { summary } = report;
      stdout(
        `Scanned ${target}: ${summary.findings} finding(s) ` +
          `(critical ${summary.critical}, high ${summary.high}, medium ${summary.medium}, low ${summary.low}).\n`,
      );
    }
  } catch (err) {
    stderr(`cryptosweep: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  }
}

async function scanClonedRepo(url: string): Promise<Awaited<ReturnType<typeof scanSource>>> {
  const repo = await cloneRepo(url);
  try {
    return await scanSource(repo.dir);
  } finally {
    await repo.cleanup();
  }
}

const cli = cac("cryptosweep");

cli
  .command("scan <target>", "Scan a host/URL (TLS posture) or a GitHub repo / local dir (source crypto)")
  .option("--out <file>", "Write the JSON report to <file>")
  .option("--md <file>", "Write the Markdown report to <file>")
  .option("--port <port>", "TLS port (defaults to 443 or the port in the target)")
  .option("--timeout <ms>", "TLS handshake timeout in milliseconds (default 10000)")
  .example("  cryptosweep scan https://www.example.com --out report.json")
  .example("  cryptosweep scan facebook/react")
  .action(runScan);

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
