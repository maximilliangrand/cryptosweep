/**
 * Target classification + scan orchestration, shared by the CLI and the MCP
 * server so both dispatch a `<target>` the same way: a hostname/URL runs the TLS
 * scanner, a GitHub shorthand/URL is shallow-cloned and scanned, and a local
 * directory is scanned in place. The option validators live here too, so both
 * front ends refuse the same bad input before any I/O happens.
 */
import { statSync } from "node:fs";
import { isIPv6 } from "node:net";
import { homedir } from "node:os";
import { resolve } from "node:path";
import type { Finding } from "./report";
import { scanTls } from "./scanners/tls";
import { scanSource } from "./scanners/source";
import { scanDeps } from "./scanners/deps";
import { reconcile } from "./reconcile";
import { cloneRepository, parseGitHubRepo } from "./clone";

export type Target =
  | { kind: "github"; url: string; owner: string; repo: string }
  | { kind: "remote"; url: string }
  | { kind: "host"; host: string; port: number }
  | { kind: "path"; dir: string };

export interface ScanTargetOptions {
  port?: number;
  timeoutMs?: number;
  allowPrivate?: boolean;
  advisories?: boolean;
  /** Permit clones from remotes other than https://github.com. CLI opt-in; never set by the MCP server. */
  allowAnyGitHost?: boolean;
  /** Aborts an in-flight clone and stops the scan before its next phase. */
  signal?: AbortSignal;
}

export interface ClassifyOptions {
  /** Resolve relative filesystem targets against this directory instead of the working directory. */
  baseDir?: string;
}

/** `./x`, `../x`, `/x`, `~`, `~/x`, `C:\x`: input that can only mean a filesystem path. */
const PATH_LIKE = /^(?:\.{1,2}(?:[/\\]|$)|[/\\]|~(?:[/\\]|$)|[A-Za-z]:[/\\])/;
const SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;
const SCP_REMOTE = /^[\w.-]+@[^:/]+:/;
const BRACKETED_HOST = /^\[([^\]]+)\](?::([^/]*))?(?:\/.*)?$/;
const BARE_HOST = /^([^/:[\]]+)(?::([^/]*))?(?:\/.*)?$/;

/** Parse an integer option within `[min, max]`, accepting a number or a decimal string. */
function parseIntegerOption(value: unknown, name: string, min: number, max: number): number {
  const parsed =
    typeof value === "number" ? value : typeof value === "string" && /^\d+$/.test(value.trim()) ? Number(value) : NaN;
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${name} must be an integer from ${min} to ${max} (got "${String(value)}")`);
  }
  return parsed;
}

/** A TCP port, 1-65535. */
export function parsePort(value: unknown, name = "port"): number {
  return parseIntegerOption(value, name, 1, 65_535);
}

/** A network timeout in milliseconds, up to ten minutes. */
export function parseTimeoutMs(value: unknown, name = "timeout"): number {
  return parseIntegerOption(value, name, 1, 600_000);
}

/** The assumed year a cryptographically relevant quantum computer exists. */
export function parseCrqcYear(value: unknown, name = "crqcYear"): number {
  return parseIntegerOption(value, name, 2020, 2100);
}

function expandHome(input: string): string {
  if (input === "~") return homedir();
  if (input.startsWith("~/") || input.startsWith("~\\")) return resolve(homedir(), input.slice(2));
  return input;
}

function statKind(path: string): "dir" | "file" | null {
  try {
    return statSync(path).isDirectory() ? "dir" : "file";
  } catch {
    return null;
  }
}

/** Canonical host name as a URL parser sees it: lower-cased, IDN to punycode, numeric IPv4 forms normalized. */
function canonicalHost(host: string, target: string): string {
  try {
    return new URL(`https://${host}`).hostname;
  } catch {
    throw new Error(`Not a valid hostname: ${target}`);
  }
}

function hostTarget(host: string, port: string | undefined, target: string): Target {
  const bare = host.replace(/^\[(.*)\]$/, "$1");
  if (!bare) throw new Error(`No host in target: ${target}`);
  return { kind: "host", host: bare, port: port === undefined || port === "" ? 443 : parsePort(port, "port in target") };
}

function classifyUrl(target: string): Target {
  const github = parseGitHubRepo(target);
  if (github) return { kind: "github", ...github };

  let url: URL;
  try {
    url = new URL(target);
  } catch {
    throw new Error(`Not a valid URL: ${target}`);
  }
  const scheme = url.protocol.replace(/:$/, "").toLowerCase();
  const host = url.hostname.replace(/^\[(.*)\]$/, "$1").toLowerCase();
  if ((host === "github.com" || host === "www.github.com") && url.pathname.replace(/\/+$/, "") !== "") {
    throw new Error(`Not a GitHub repository URL: ${target} (expected https://github.com/<owner>/<repo>)`);
  }
  if (scheme === "ssh" || scheme === "git+ssh" || scheme === "git" || url.pathname.endsWith(".git")) {
    return { kind: "remote", url: target };
  }
  if (scheme === "file") throw new Error(`Not a network target: ${target} (pass the directory path instead)`);
  return hostTarget(host, url.port, target);
}

/**
 * Decide what kind of thing `target` is and how to scan it. The order matters:
 * explicit paths, then existing directories, then URLs and git remotes, then IP
 * literals, then GitHub shorthand, and a bare `host[:port]` last. Throws on
 * input that fits none of them rather than guessing.
 */
export function classifyTarget(target: string, options: ClassifyOptions = {}): Target {
  const input = target.trim();
  if (!input) throw new Error("target is required");
  const expanded = expandHome(input);
  const dir = options.baseDir === undefined ? expanded : resolve(options.baseDir, expanded);

  if (PATH_LIKE.test(input)) return { kind: "path", dir };
  const existing = statKind(dir);
  if (existing === "dir") return { kind: "path", dir };
  if (existing === "file") throw new Error(`${input} is a file; pass the directory that contains it`);

  if (SCHEME.test(input)) return classifyUrl(input);
  if (SCP_REMOTE.test(input)) return { kind: "remote", url: input };

  const bracketed = BRACKETED_HOST.exec(input);
  if (bracketed) {
    const [, address = "", port] = bracketed;
    if (!isIPv6(address)) throw new Error(`Not a valid IPv6 address: ${input}`);
    return hostTarget(address, port, input);
  }
  if (isIPv6(input)) return { kind: "host", host: input, port: 443 };

  const github = parseGitHubRepo(input);
  if (github) return { kind: "github", ...github };

  const bare = BARE_HOST.exec(input);
  if (!bare) throw new Error(`Not a hostname, URL, GitHub repository or directory: ${input}`);
  const [, host = "", port] = bare;
  return hostTarget(canonicalHost(host, input), port, input);
}

/** Scan a local directory: source + dependency manifests, then reconcile the two. */
export async function scanLocalDir(dir: string, advisories = false): Promise<Finding[]> {
  const [source, deps] = await Promise.all([
    scanSource(dir),
    scanDeps(dir, advisories ? { advisories: { enabled: true } } : {}),
  ]);
  return reconcile([...source, ...deps]);
}

/** Shallow-clone a repo through the hardened clone path, scan it, and clean up. */
export async function scanClonedRepo(url: string, options: ScanTargetOptions = {}): Promise<Finding[]> {
  const repo = await cloneRepository(url, {
    allowAnyHost: options.allowAnyGitHost === true,
    allowPrivate: options.allowPrivate === true,
    signal: options.signal,
  });
  try {
    options.signal?.throwIfAborted();
    return await scanLocalDir(repo.dir, options.advisories);
  } finally {
    await repo.cleanup();
  }
}

/** Classify `target` (unless the caller already did) and run the appropriate scanner(s). */
export async function scanTarget(target: string | Target, options: ScanTargetOptions = {}): Promise<Finding[]> {
  const parsed = typeof target === "string" ? classifyTarget(target) : target;
  options.signal?.throwIfAborted();
  switch (parsed.kind) {
    case "host":
      return scanTls(parsed.host, {
        port: options.port ?? parsed.port,
        timeoutMs: options.timeoutMs ?? 10_000,
        allowPrivate: options.allowPrivate,
      });
    case "path":
      if (statKind(parsed.dir) !== "dir") throw new Error(`No such directory: ${parsed.dir}`);
      return scanLocalDir(parsed.dir, options.advisories);
    case "github":
    case "remote":
      return scanClonedRepo(parsed.url, options);
  }
}
