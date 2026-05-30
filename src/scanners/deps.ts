/**
 * Dependency-audit scanner.
 *
 * Walks a local directory, finds known manifest files across the three
 * supported ecosystems (npm / python / cargo), runs the matching parser on
 * each, and maps the result against the registry. No network access.
 */
import { readdir, readFile } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import type { Finding } from "../report";
import type { Ecosystem, RegistryEntry } from "./deps/registry";
import { REGISTRY } from "./deps/registry";
import { parsePackageJson, parsePnpmLock, type ParsedDep } from "./deps/parsers/npm";
import { parsePyproject, parseRequirementsTxt } from "./deps/parsers/python";
import { parseCargoToml } from "./deps/parsers/cargo";

export type { ParsedDep } from "./deps/parsers/npm";

export interface DepsScanOptions {
  ignoreDirs?: string[];
  /** Files larger than this (bytes) are skipped. */
  maxFileBytes?: number;
}

const DEFAULT_IGNORE_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "coverage",
  ".next",
  "out",
  "vendor",
  ".turbo",
  "target", // rust build output
  ".venv",
  "venv",
  "__pycache__",
]);

const DEFAULT_MAX_FILE_BYTES = 5_000_000;

class IdAllocator {
  private counter = 0;

  next(): string {
    this.counter += 1;
    return `CSW-DEP-${String(this.counter).padStart(3, "0")}`;
  }
}

function registryLookup(name: string, ecosystem: Ecosystem): RegistryEntry | undefined {
  return REGISTRY.find((entry) => entry.name === name && entry.ecosystem === ecosystem);
}

function toFinding(dep: ParsedDep, entry: RegistryEntry, ids: IdAllocator): Finding {
  const versionLabel = dep.version || "*";
  return {
    id: ids.next(),
    severity: entry.severity,
    category: "deps",
    title: `${entry.name} (${dep.ecosystem}) — ${entry.reason}`,
    evidence: `${dep.manifestPath}:${dep.name}@${versionLabel}`,
    pq_status: entry.pq_status,
    recommendation: entry.recommendation,
  };
}

/** Pure helper: map parsed deps against the registry into Findings. */
export function matchDeps(deps: readonly ParsedDep[], ids: IdAllocator = new IdAllocator()): Finding[] {
  const out: Finding[] = [];
  const seenEvidence = new Set<string>();
  for (const dep of deps) {
    const entry = registryLookup(dep.name, dep.ecosystem);
    if (!entry) continue;
    const finding = toFinding(dep, entry, ids);
    if (seenEvidence.has(finding.evidence)) continue;
    seenEvidence.add(finding.evidence);
    out.push(finding);
  }
  return out;
}

interface ManifestHit {
  ecosystem: Ecosystem;
  kind: "package.json" | "pnpm-lock" | "requirements.txt" | "pyproject.toml" | "Cargo.toml";
  absPath: string;
  manifestPath: string;
}

function classifyManifest(filename: string): ManifestHit["kind"] | null {
  if (filename === "package.json") return "package.json";
  if (filename === "pnpm-lock.yaml") return "pnpm-lock";
  if (filename === "requirements.txt") return "requirements.txt";
  if (filename === "pyproject.toml") return "pyproject.toml";
  if (filename === "Cargo.toml") return "Cargo.toml";
  return null;
}

function ecosystemFor(kind: ManifestHit["kind"]): Ecosystem {
  if (kind === "package.json" || kind === "pnpm-lock") return "npm";
  if (kind === "requirements.txt" || kind === "pyproject.toml") return "python";
  return "cargo";
}

async function findManifests(
  rootDir: string,
  ignoreDirs: Set<string>,
): Promise<ManifestHit[]> {
  const hits: ManifestHit[] = [];
  const stack: string[] = [rootDir];
  while (stack.length > 0) {
    const dir = stack.pop();
    if (dir === undefined) break;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (ignoreDirs.has(entry.name)) continue;
        stack.push(full);
        continue;
      }
      if (!entry.isFile()) continue;
      const kind = classifyManifest(entry.name);
      if (!kind) continue;
      const rel = relative(rootDir, full) || entry.name;
      hits.push({
        kind,
        ecosystem: ecosystemFor(kind),
        absPath: full,
        manifestPath: rel.split(sep).join("/"),
      });
    }
  }
  return hits;
}

async function readSafe(path: string, maxBytes: number): Promise<string | null> {
  try {
    const buffer = await readFile(path);
    if (buffer.byteLength > maxBytes) return null;
    return buffer.toString("utf8");
  } catch {
    return null;
  }
}

async function parseManifest(hit: ManifestHit, maxBytes: number): Promise<ParsedDep[]> {
  const content = await readSafe(hit.absPath, maxBytes);
  if (content === null) return [];
  switch (hit.kind) {
    case "package.json":
      return parsePackageJson(content, hit.manifestPath);
    case "pnpm-lock":
      return parsePnpmLock(content, hit.manifestPath);
    case "requirements.txt":
      return parseRequirementsTxt(content, hit.manifestPath);
    case "pyproject.toml":
      return parsePyproject(content, hit.manifestPath);
    case "Cargo.toml":
      return parseCargoToml(content, hit.manifestPath);
  }
}

/** Walk `rootDir`, parse every recognised manifest, return aggregated Findings. */
export async function scanDeps(rootDir: string, options: DepsScanOptions = {}): Promise<Finding[]> {
  const ignoreDirs = new Set([...DEFAULT_IGNORE_DIRS, ...(options.ignoreDirs ?? [])]);
  const maxBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const hits = await findManifests(rootDir, ignoreDirs);
  const allDeps: ParsedDep[] = [];
  for (const hit of hits) {
    allDeps.push(...(await parseManifest(hit, maxBytes)));
  }
  return matchDeps(allDeps);
}
