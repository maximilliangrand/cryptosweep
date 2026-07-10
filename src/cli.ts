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
import { cac } from "cac";
import { buildReport, failsThreshold, toJson, toMarkdown } from "./report";
import type { Report, Severity } from "./report";
import { toCbom } from "./output/cbom";
import { toSarif } from "./output/sarif";
import { toHtml } from "./output/viewer";
import { assessRisk } from "./model/risk";
import type { RiskModel } from "./model/risk";
import { DATA_CLASSES, defaultProfile, isDataClassId } from "./model/estate";
import { classifyTarget, scanTarget } from "./orchestrate";
import { renderHtml, renderText } from "./email/render";
import { sendEmail } from "./email/resend";
import { VERSION } from "./version";

interface ScanOptions {
  out?: string;
  md?: string;
  cbom?: string;
  sarif?: string;
  html?: string;
  failOn?: string;
  allowPrivate?: boolean;
  advisories?: boolean;
  dataClass?: string;
  crqcYear?: string | number;
  risk?: string;
  port?: string | number;
  timeout?: string | number;
}

const SEVERITIES: ReadonlySet<string> = new Set(["critical", "high", "medium", "low", "info"]);

const stdout = (text: string): void => void process.stdout.write(text);
const stderr = (text: string): void => void process.stderr.write(text);

async function runScan(target: string, options: ScanOptions): Promise<void> {
  try {
    const findings = await scanTarget(target, {
      port: options.port ? Number(options.port) : undefined,
      timeoutMs: options.timeout ? Number(options.timeout) : undefined,
      allowPrivate: options.allowPrivate,
      advisories: Boolean(options.advisories),
    });

    if (options.advisories && classifyTarget(target).kind !== "host") {
      stderr(
        "cryptosweep: --advisories posts flagged, version-pinned dependencies to api.osv.dev for a known-CVE lookup.\n",
      );
    }

    const report = buildReport(target, findings);

    if (options.dataClass && !isDataClassId(options.dataClass)) {
      throw new Error(`--data-class must be one of ${DATA_CLASSES.map((c) => c.id).join(", ")}`);
    }
    const profile = defaultProfile(report.scanned_at, {
      dataClassId: options.dataClass,
      crqcYear: options.crqcYear ? Number(options.crqcYear) : undefined,
    });
    const risk = assessRisk(target, report.findings, profile);

    if (options.out) await writeFile(options.out, `${toJson(report)}\n`, "utf8");
    if (options.md) await writeFile(options.md, `${toMarkdown(report)}\n`, "utf8");
    if (options.cbom) await writeFile(options.cbom, `${toCbom(report)}\n`, "utf8");
    if (options.sarif) await writeFile(options.sarif, `${toSarif(report)}\n`, "utf8");
    if (options.html) await writeFile(options.html, toHtml(report, risk), "utf8");
    if (options.risk) await writeFile(options.risk, `${JSON.stringify(risk, null, 2)}\n`, "utf8");

    const wroteFile = Boolean(
      options.out || options.md || options.cbom || options.sarif || options.html || options.risk,
    );
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

    stderr(formatRisk(risk));

    if (options.failOn) {
      const threshold = options.failOn.toLowerCase();
      if (!SEVERITIES.has(threshold)) {
        throw new Error(`--fail-on must be one of critical|high|medium|low|info (got "${options.failOn}")`);
      }
      if (failsThreshold(report, threshold as Severity)) {
        stderr(`cryptosweep: findings at or above "${threshold}", failing (exit 2).\n`);
        process.exitCode = 2;
      }
    }
  } catch (err) {
    stderr(`cryptosweep: ${describeError(err)}\n`);
    process.exitCode = 1;
  }
}

/** A compact crypto-agility risk summary for stderr (keeps stdout artifacts clean). */
function formatRisk(risk: RiskModel): string {
  const l = risk.ledger;
  const a = risk.assumptions;
  return (
    `crypto-agility risk (data class ${a.dataClass}, ${a.horizonYears}yr horizon, CRQC assumed ${a.crqcYear}):\n` +
    `  exposed(HNDL) ${l.exposedAssets}  overdue ${l.overdueAssets}  act-now(classical) ${l.actNowAssets}  ` +
    `on-track ${l.onTrackAssets}  |  ${Math.round(l.exposureRiskYears)} risk-years exposed\n` +
    `  ${l.headline}\n`
  );
}

/** Render an error for the user, never leaving an empty message (e.g. a bare socket error). */
function describeError(err: unknown): string {
  if (err instanceof Error) {
    const code = (err as NodeJS.ErrnoException).code;
    if (err.message) return code ? `${err.message} (${code})` : err.message;
    if (code) return `network error: ${code}`;
    return err.name || "unknown error";
  }
  const text = String(err);
  return text && text !== "[object Object]" ? text : "unknown error";
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
    const subject = options.subject ?? `cryptosweep PQ readiness report, ${report.target}`;
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
  .option("--html <file>", "Write a self-contained interactive HTML report to <file>")
  .option("--fail-on <severity>", "Exit non-zero if any finding is at/above this severity")
  .option("--allow-private", "Allow scanning non-public addresses (localhost, RFC 1918)")
  .option("--advisories", "Opt-in: cross-reference flagged deps against OSV.dev for known CVEs (network, off by default)")
  .option("--data-class <class>", "Data confidentiality class for the Mosca-clock risk model (e.g. legal-privileged)")
  .option("--crqc-year <year>", "Assumed year a cryptographically-relevant quantum computer exists (default 2035)")
  .option("--risk <file>", "Write the crypto-agility risk model (Mosca clock + harvest ledger) to <file>")
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
