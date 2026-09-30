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
import { resolve } from "node:path";
import { cac } from "cac";
import { buildReport, failsThreshold, toJson, toMarkdown } from "./report";
import type { Report, Severity } from "./report";
import { toCbom } from "./output/cbom";
import { toSarif } from "./output/sarif";
import { toHtml } from "./output/viewer";
import { assessRisk } from "./model/risk";
import type { RiskModel } from "./model/risk";
import { DATA_CLASSES, defaultProfile, isDataClassId } from "./model/estate";
import {
  classifyTarget,
  describeCoverage,
  parseCrqcYear,
  parseMigrationYears,
  parsePort,
  parseTimeoutMs,
  scanTarget,
} from "./orchestrate";
import type { ScanTargetOptions, Target } from "./orchestrate";
import { VERSION } from "./version";

interface ScanOptions {
  out?: string | number;
  md?: string | number;
  cbom?: string | number;
  sarif?: string | number;
  html?: string | number;
  failOn?: string;
  allowPrivate?: boolean;
  allowAnyGitHost?: boolean;
  advisories?: boolean;
  dataClass?: string;
  crqcYear?: string | number;
  migrationYears?: string | number;
  risk?: string | number;
  port?: string | number;
  timeout?: string | number;
}

const SEVERITIES: ReadonlySet<string> = new Set(["critical", "high", "medium", "low", "info"]);

const OUTPUT_FLAGS = ["out", "md", "cbom", "sarif", "html", "risk"] as const;
type OutputFlag = (typeof OUTPUT_FLAGS)[number];

/** Everything a scan needs, validated up front so bad input fails before any network I/O or file write. */
interface ScanPlan {
  target: Target;
  scan: ScanTargetOptions;
  dataClass?: string;
  crqcYear?: number;
  migrationYears?: number;
  failOn?: Severity;
  outputs: Partial<Record<OutputFlag, string>>;
}

const stdout = (text: string): void => void process.stdout.write(text);
const stderr = (text: string): void => void process.stderr.write(text);

/** cac turns numeric-looking values into numbers; a file flag must stay a path, never a file descriptor. */
function outputPaths(options: ScanOptions): Partial<Record<OutputFlag, string>> {
  const outputs: Partial<Record<OutputFlag, string>> = {};
  const seen = new Map<string, OutputFlag>();
  for (const flag of OUTPUT_FLAGS) {
    const value = options[flag];
    if (value === undefined) continue;
    const path = String(value);
    if (!path.trim()) throw new Error(`--${flag} needs a file path`);
    const previous = seen.get(resolve(path));
    if (previous) throw new Error(`--${previous} and --${flag} would both write ${path}`);
    seen.set(resolve(path), flag);
    outputs[flag] = path;
  }
  return outputs;
}

function planScan(input: string, options: ScanOptions): ScanPlan {
  const target = classifyTarget(input);
  const isHost = target.kind === "host";

  let failOn: Severity | undefined;
  if (options.failOn !== undefined) {
    const threshold = String(options.failOn).toLowerCase();
    if (!SEVERITIES.has(threshold)) {
      throw new Error(`--fail-on must be one of critical|high|medium|low|info (got "${String(options.failOn)}")`);
    }
    failOn = threshold as Severity;
  }
  if (options.dataClass !== undefined && !isDataClassId(String(options.dataClass))) {
    throw new Error(`--data-class must be one of ${DATA_CLASSES.map((c) => c.id).join(", ")}`);
  }
  const crqcYear = options.crqcYear === undefined ? undefined : parseCrqcYear(options.crqcYear, "--crqc-year");
  const migrationYears =
    options.migrationYears === undefined ? undefined : parseMigrationYears(options.migrationYears, "--migration-years");
  const port = options.port === undefined ? undefined : parsePort(options.port, "--port");
  const timeoutMs = options.timeout === undefined ? undefined : parseTimeoutMs(options.timeout, "--timeout");

  if (!isHost && port !== undefined) throw new Error("--port applies only to hostname/URL (TLS) targets");
  if (!isHost && timeoutMs !== undefined) throw new Error("--timeout applies only to hostname/URL (TLS) targets");
  if (isHost && options.advisories) {
    throw new Error("--advisories applies only to repository and directory targets (it checks dependency manifests)");
  }

  return {
    target,
    scan: {
      port,
      timeoutMs,
      allowPrivate: options.allowPrivate === true,
      allowAnyGitHost: options.allowAnyGitHost === true,
      advisories: options.advisories === true,
    },
    dataClass: options.dataClass === undefined ? undefined : String(options.dataClass),
    crqcYear,
    migrationYears,
    failOn,
    outputs: outputPaths(options),
  };
}

async function writeOutputs(plan: ScanPlan, report: Report, risk: RiskModel): Promise<boolean> {
  const { outputs } = plan;
  if (outputs.out) await writeFile(outputs.out, `${toJson(report)}\n`, "utf8");
  if (outputs.md) await writeFile(outputs.md, `${toMarkdown(report)}\n`, "utf8");
  if (outputs.cbom) await writeFile(outputs.cbom, `${toCbom(report)}\n`, "utf8");
  if (outputs.sarif) await writeFile(outputs.sarif, `${toSarif(report)}\n`, "utf8");
  if (outputs.html) await writeFile(outputs.html, toHtml(report, risk), "utf8");
  if (outputs.risk) await writeFile(outputs.risk, `${JSON.stringify(risk, null, 2)}\n`, "utf8");
  return Object.keys(outputs).length > 0;
}

async function runScan(target: string, options: ScanOptions): Promise<void> {
  try {
    const plan = planScan(target, options);

    // The disclosure comes before the scan, because the scan is what sends the data.
    if (plan.scan.advisories) {
      stderr(
        "cryptosweep: --advisories posts flagged, version-pinned dependencies to api.osv.dev for a known-CVE lookup.\n",
      );
    }

    const findings = await scanTarget(plan.target, plan.scan);
    const report = buildReport(target, findings, new Date(), describeCoverage(plan.target, findings));
    const profile = defaultProfile(report.scanned_at, {
      dataClassId: plan.dataClass,
      crqcYear: plan.crqcYear,
      migrationYears: plan.migrationYears,
    });
    const risk = assessRisk(target, report.findings, profile);

    if (!(await writeOutputs(plan, report, risk))) {
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

    if (plan.failOn && failsThreshold(report, plan.failOn)) {
      stderr(`cryptosweep: findings at or above "${plan.failOn}", failing (exit 2).\n`);
      process.exitCode = 2;
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
  .option(
    "--allow-any-git-host",
    "Allow cloning from https hosts other than github.com and from ssh remotes (git@host:path)",
  )
  .option("--advisories", "Opt-in: cross-reference flagged deps against OSV.dev for known CVEs (network, off by default)")
  .option("--data-class <class>", "Data confidentiality class for the Mosca-clock risk model (e.g. legal-privileged)")
  .option(
    "--crqc-year <year>",
    "Assumed year a cryptographically-relevant quantum computer exists, 2020-2100 (default 2035)",
  )
  .option(
    "--migration-years <years>",
    "Years a migration takes (Mosca's Y), applied to every asset (default 3 for key establishment, 5 for signatures)",
  )
  .option("--risk <file>", "Write the crypto-agility risk model (Mosca clock + harvest ledger) to <file>")
  .option("--port <port>", "TLS port, 1-65535 (defaults to 443 or the port in the target)")
  .option("--timeout <ms>", "TLS handshake timeout in milliseconds (default 10000)")
  .example("  cryptosweep scan https://www.example.com --out report.json --cbom cbom.json")
  .example("  cryptosweep scan facebook/react --sarif results.sarif --fail-on high")
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
