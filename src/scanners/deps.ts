/**
 * Dependency-audit scanner.
 *
 * Walks a local directory, finds known manifest files across the three
 * supported ecosystems (npm / python / cargo), runs the matching parser on
 * each, and maps the result against the registry. No network access.
 */
import { readdir, readFile } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import type { Confidence, Finding, PqStatus, Reference, Severity } from "../report";
import type { Ecosystem, RegistryEntry } from "./deps/registry";
import { lookupEntry } from "./deps/registry";
import { REFS } from "../crypto";
import { parsePackageJson, parsePnpmLock, type ParsedDep } from "./deps/parsers/npm";
import { parsePyproject, parseRequirementsTxt } from "./deps/parsers/python";
import { parseCargoToml } from "./deps/parsers/cargo";
import { annotateWithAdvisories } from "./deps/advisories";
import type { AdvisoryOptions } from "./deps/advisories";

export type { ParsedDep } from "./deps/parsers/npm";

export interface DepsScanOptions {
  ignoreDirs?: string[];
  /** Files larger than this (bytes) are skipped. */
  maxFileBytes?: number;
  /** Opt-in OSV.dev advisory enrichment (network). Off unless enabled. */
  advisories?: AdvisoryOptions;
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

/** Extract a comparable numeric version from a manifest spec (e.g. "^9.0.0" -> [9,0,0]). */
export function extractVersion(spec: string | undefined): number[] | null {
  if (!spec) return null;
  const match = /(\d+(?:\.\d+)*)/.exec(spec);
  if (!match?.[1]) return null;
  const parts = match[1].split(".").map((n) => Number.parseInt(n, 10));
  return parts.every((n) => Number.isFinite(n)) ? parts : null;
}

/** Compare two numeric versions. Missing components are treated as 0. */
function compareVersions(a: number[], b: number[]): number {
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i += 1) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

interface Assessment {
  severity: Severity;
  pq_status: PqStatus;
  confidence: Confidence;
  recommendation: string;
}

/**
 * Assess a dependency against its registry entry, taking the declared version
 * into account when the entry records a `fixedIn`. Libraries that are classical
 * by nature (no `fixedIn`) are flagged at every version, as they should be.
 */
function assess(dep: ParsedDep, entry: RegistryEntry): Assessment {
  if (!entry.fixedIn) {
    return { severity: entry.severity, pq_status: entry.pq_status, confidence: "medium", recommendation: entry.recommendation };
  }
  const declared = extractVersion(dep.version);
  const fixed = extractVersion(entry.fixedIn);
  if (!declared || !fixed) {
    return {
      severity: entry.severity,
      pq_status: entry.pq_status,
      confidence: "low",
      recommendation: `Could not resolve a concrete version; flagged conservatively. The PQ-relevant fix landed in ${entry.name} ${entry.fixedIn}. ${entry.recommendation}`,
    };
  }
  if (compareVersions(declared, fixed) < 0) {
    return {
      severity: entry.severity,
      pq_status: entry.pq_status,
      confidence: "high",
      recommendation: `${dep.name} ${dep.version} predates ${entry.fixedIn}. ${entry.recommendation}`,
    };
  }
  return {
    severity: "info",
    pq_status: "transitional",
    confidence: "high",
    recommendation: `${dep.name} ${dep.version} is at or above ${entry.fixedIn}, which carries the PQ-relevant support, confirm it is enabled in configuration.`,
  };
}

function referencesFor(pq: PqStatus): Reference[] {
  if (pq === "vulnerable") return [REFS.cnsa2, REFS.ir8547];
  if (pq === "transitional") return [REFS.fips203];
  return [];
}

/** Merge references keeping first occurrence per label, stable order. */
function dedupeByLabel(refs: Reference[]): Reference[] {
  const seen = new Set<string>();
  const out: Reference[] = [];
  for (const ref of refs) {
    if (!seen.has(ref.label)) {
      seen.add(ref.label);
      out.push(ref);
    }
  }
  return out;
}

function toFinding(dep: ParsedDep, entry: RegistryEntry, ids: IdAllocator): Finding {
  const versionLabel = dep.version || "*";
  const a = assess(dep, entry);
  return {
    id: ids.next(),
    ruleId: `deps/${dep.ecosystem}-${entry.name}`,
    severity: a.severity,
    category: "deps",
    title: `${entry.name} (${dep.ecosystem}): ${entry.reason}`,
    evidence: `${dep.manifestPath}:${dep.name}@${versionLabel}`,
    location: { path: dep.manifestPath },
    pq_status: a.pq_status,
    confidence: a.confidence,
    recommendation: a.recommendation,
    // Entry-specific provenance first, then the generic standards for the
    // assessed posture (so rustls >= 0.23, now transitional, keeps FIPS 203).
    references: dedupeByLabel([...(entry.references ?? []), ...referencesFor(a.pq_status)]),
  };
}

/** Pure helper: map parsed deps against the registry into Findings. */
export function matchDeps(deps: readonly ParsedDep[], ids: IdAllocator = new IdAllocator()): Finding[] {
  const out: Finding[] = [];
  const seenEvidence = new Set<string>();
  for (const dep of deps) {
    const entry = lookupEntry(dep.name, dep.ecosystem);
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
  const findings = matchDeps(allDeps);
  if (options.advisories?.enabled) {
    return annotateWithAdvisories(findings, allDeps, options.advisories);
  }
  return findings;
}
