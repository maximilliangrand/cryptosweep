/**
 * npm-ecosystem dependency parsers.
 *
 * Parses `package.json` (direct deps across all groups) and the three npm
 * lockfile formats, which carry resolved versions including transitive deps:
 * `pnpm-lock.yaml`, `package-lock.json` / `npm-shrinkwrap.json`, and
 * `yarn.lock` (v1 and berry). Deterministic over its input; no network or fs.
 */
import type { Ecosystem } from "../registry";

export interface ParsedDep {
  name: string;
  /** Raw version string from the manifest. May be a range like "^1.0.0", or "" if unknown. */
  version: string;
  /**
   * The constraint as it applies, when `version` alone does not say it: a
   * Python specifier with its operators (`>=41,<47`, where `version` is `41`),
   * or Cargo's implicit caret made explicit (`0.23` declares `^0.23`).
   */
  constraint?: string;
  ecosystem: Ecosystem;
  /** Manifest path relative to the scan root (caller-supplied). */
  manifestPath: string;
}

const DEP_GROUPS = [
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "optionalDependencies",
] as const;

interface PackageJsonShape {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

function isStringRecord(value: unknown): value is Record<string, string> {
  if (value === null || typeof value !== "object") return false;
  return Object.values(value as Record<string, unknown>).every((v) => typeof v === "string");
}

/** Parse a `package.json` file. Returns one entry per direct dep across all dep groups. */
export function parsePackageJson(content: string, manifestPath: string): ParsedDep[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }
  if (parsed === null || typeof parsed !== "object") return [];
  const pkg = parsed as PackageJsonShape;

  const seen = new Set<string>();
  const deps: ParsedDep[] = [];
  for (const group of DEP_GROUPS) {
    const groupValue = pkg[group];
    if (!isStringRecord(groupValue)) continue;
    for (const [name, version] of Object.entries(groupValue)) {
      if (seen.has(name)) continue;
      seen.add(name);
      deps.push({ name, version, ecosystem: "npm", manifestPath });
    }
  }
  return deps;
}

/**
 * An indented `name@version:` or `/name@version:` key (the leading slash is the
 * older pnpm style; @-prefixed names need a second @). Applied to one line at a
 * time with `[ \t]` indentation: the old multiline `^\s{2,}` also consumed
 * newlines and backtracked quadratically over a run of blank lines.
 */
const PNPM_KEY = /^[ \t]{2,}\/?((?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*)@([^\s'"():]+):[ \t]*$/i;

/**
 * Parse a `pnpm-lock.yaml` file. Extracts resolved `name@version` pairs from
 * either the v6/v7 `packages: /name@version:` form or the v9 `name@version:`
 * form. Scoped packages (e.g. `@scope/pkg`) are handled.
 */
export function parsePnpmLock(content: string, manifestPath: string): ParsedDep[] {
  const seen = new Set<string>();
  const deps: ParsedDep[] = [];
  for (const line of content.split("\n")) {
    const m = PNPM_KEY.exec(line.endsWith("\r") ? line.slice(0, -1) : line);
    if (!m) continue;
    const name = m[1];
    const version = m[2];
    if (!name || !version) continue;
    // Skip aliases / link: / file: pseudo-versions and pnpm peer-suffixed keys.
    if (version.startsWith("link:") || version.startsWith("file:")) continue;
    const key = `${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deps.push({ name, version, ecosystem: "npm", manifestPath });
  }
  return deps;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** `package-lock.json` v1 nests `dependencies` recursively; bound the walk against a hostile file. */
const MAX_LOCK_DEPTH = 64;

/** Collects `name@version` pairs, once each. */
function lockCollector(manifestPath: string): { deps: ParsedDep[]; add: (name: string, version: string) => void } {
  const seen = new Set<string>();
  const deps: ParsedDep[] = [];
  return {
    deps,
    add: (name, version) => {
      const key = `${name}@${version}`;
      if (!name || seen.has(key)) return;
      seen.add(key);
      deps.push({ name, version, ecosystem: "npm", manifestPath });
    },
  };
}

/**
 * Parse a `package-lock.json` or `npm-shrinkwrap.json`: every installed
 * package, direct and transitive. Lockfile v2/v3 list them under `packages`
 * keyed by install path (`node_modules/a/node_modules/b`, an alias carries its
 * real `name`); v1 nests them under `dependencies`.
 */
export function parsePackageLock(content: string, manifestPath: string): ParsedDep[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }
  const out = lockCollector(manifestPath);
  if (!isRecord(parsed)) return out.deps;
  if (isRecord(parsed.packages)) {
    for (const [path, entry] of Object.entries(parsed.packages)) {
      const at = path.lastIndexOf("node_modules/");
      if (at < 0 || !isRecord(entry) || entry.link === true) continue; // the root and workspace sources
      const name = typeof entry.name === "string" ? entry.name : path.slice(at + "node_modules/".length);
      out.add(name, typeof entry.version === "string" ? entry.version : "");
    }
    return out.deps;
  }
  const stack: Array<{ deps: unknown; depth: number }> = [{ deps: parsed.dependencies, depth: 0 }];
  for (let next = stack.pop(); next; next = stack.pop()) {
    if (!isRecord(next.deps) || next.depth > MAX_LOCK_DEPTH) continue;
    for (const [name, entry] of Object.entries(next.deps)) {
      if (!isRecord(entry)) continue;
      out.add(name, typeof entry.version === "string" ? entry.version : "");
      stack.push({ deps: entry.dependencies, depth: next.depth + 1 });
    }
  }
  return out.deps;
}

/** `  version "1.2.3"` (yarn v1) or `  version: 1.2.3` (yarn berry). */
const YARN_VERSION = /^ {2}version:? {1,8}"?([^"\s]{1,128})"?[ \t]*$/;

/** The package name of a yarn entry header (`"@scope/a@^1.0", "@scope/a@^1.1":` or `a@npm:^1.0:`). */
function yarnEntryName(header: string): string | null {
  const first = (header.split(",")[0] ?? "").trim().replace(/^"|"$/g, "");
  const at = first.indexOf("@", first.startsWith("@") ? 1 : 0);
  return at > 0 ? first.slice(0, at) : null;
}

/**
 * Parse a `yarn.lock`, v1 or berry (v2+). Both are line-oriented: an
 * unindented entry header naming one or more descriptors, then an indented
 * `version` field. One pass, one line at a time.
 */
export function parseYarnLock(content: string, manifestPath: string): ParsedDep[] {
  const out = lockCollector(manifestPath);
  let current: string | null = null;
  for (const raw of content.split("\n")) {
    const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
    if (line === "" || line.startsWith("#")) continue;
    if (!line.startsWith(" ")) {
      current = line.endsWith(":") ? yarnEntryName(line.slice(0, -1)) : null;
      continue;
    }
    if (current === null) continue;
    const match = YARN_VERSION.exec(line);
    if (match?.[1]) {
      out.add(current, match[1]);
      current = null;
    }
  }
  return out.deps;
}
