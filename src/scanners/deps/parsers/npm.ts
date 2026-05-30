/**
 * npm-ecosystem dependency parsers.
 *
 * Parses `package.json` (direct deps across all groups) and pnpm-lock.yaml
 * (resolved versions, including transitive). Deterministic over its input;
 * no network or fs.
 */
import type { Ecosystem } from "../registry";

export interface ParsedDep {
  name: string;
  /** Raw version string from the manifest. May be a range like "^1.0.0", or "" if unknown. */
  version: string;
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
 * Parse a `pnpm-lock.yaml` file. Extracts resolved `name@version` pairs from
 * either the v6/v7 `packages: /name@version:` form or the v9 `name@version:`
 * form. Scoped packages (e.g. `@scope/pkg`) are handled.
 */
export function parsePnpmLock(content: string, manifestPath: string): ParsedDep[] {
  const seen = new Set<string>();
  const deps: ParsedDep[] = [];
  // Match indented `keys` that look like `name@version:` or `/name@version:`.
  // The leading slash is the older pnpm style; @-prefixed names need a second @.
  const re = /^\s{2,}\/?((?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*)@([^\s'"():]+):\s*$/gim;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
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
