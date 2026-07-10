/**
 * Target classification + scan orchestration, shared by the CLI and the MCP
 * server so both dispatch a `<target>` the same way: a hostname/URL runs the TLS
 * scanner, a GitHub shorthand/URL is shallow-cloned and scanned, and a local
 * directory is scanned in place.
 */
import { existsSync, statSync } from "node:fs";
import type { Finding } from "./report";
import { scanTls } from "./scanners/tls";
import { cloneRepo, scanSource } from "./scanners/source";
import { scanDeps } from "./scanners/deps";

export type Target =
  | { kind: "github"; url: string }
  | { kind: "host"; host: string; port: number }
  | { kind: "path"; dir: string };

export interface ScanTargetOptions {
  port?: number;
  timeoutMs?: number;
  allowPrivate?: boolean;
  advisories?: boolean;
}

/** Decide what kind of thing `target` is and how to scan it. */
export function classifyTarget(target: string): Target {
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

/** Scan a local directory: source + dependency manifests. */
export async function scanLocalDir(dir: string, advisories = false): Promise<Finding[]> {
  const [source, deps] = await Promise.all([
    scanSource(dir),
    scanDeps(dir, advisories ? { advisories: { enabled: true } } : {}),
  ]);
  return [...source, ...deps];
}

/** Shallow-clone a repo, scan it, and clean up. */
export async function scanClonedRepo(url: string, advisories = false): Promise<Finding[]> {
  const repo = await cloneRepo(url);
  try {
    return await scanLocalDir(repo.dir, advisories);
  } finally {
    await repo.cleanup();
  }
}

/** Classify `target` and run the appropriate scanner(s). */
export async function scanTarget(target: string, options: ScanTargetOptions = {}): Promise<Finding[]> {
  const parsed = classifyTarget(target);
  if (parsed.kind === "host") {
    return scanTls(parsed.host, {
      port: options.port ?? parsed.port,
      timeoutMs: options.timeoutMs ?? 10_000,
      allowPrivate: options.allowPrivate,
    });
  }
  if (parsed.kind === "path") return scanLocalDir(parsed.dir, options.advisories);
  return scanClonedRepo(parsed.url, options.advisories);
}
