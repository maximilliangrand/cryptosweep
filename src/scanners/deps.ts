/**
 * Dependency-audit scanner.
 *
 * Walks a local directory, finds known manifest and lockfile formats across the
 * three supported ecosystems (npm / python / cargo), runs the matching parser
 * on each, and maps the result against the registry. No network access.
 *
 * Coverage is explicit: a dependency file in a format cryptosweep does not
 * parse (go.mod, pom.xml, Gemfile.lock, ...), a manifest over the size limit,
 * and a walk stopped at its budget each produce an `info` finding, so "no
 * findings" never silently means "not analysed". Sizes are checked on the open
 * handle before any read, and entries are visited in sorted order.
 */
import { constants } from "node:fs";
import type { Dirent } from "node:fs";
import { open, opendir } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import type { Confidence, Finding, PqStatus, Reference, Severity } from "../report";
import type { Ecosystem, RegistryEntry } from "./deps/registry";
import { depsRuleId, lookupEntry } from "./deps/registry";
import { REFS } from "../crypto";
import { parsePackageJson, parsePackageLock, parsePnpmLock, parseYarnLock, type ParsedDep } from "./deps/parsers/npm";
import {
  normalizePythonName,
  parsePipfile,
  parsePipfileLock,
  parsePyproject,
  parsePythonLock,
  parseRequirementsTxt,
} from "./deps/parsers/python";
import { parseCargoLock, parseCargoToml } from "./deps/parsers/cargo";
import { annotateWithAdvisories } from "./deps/advisories";
import type { AdvisoryOptions } from "./deps/advisories";

export type { ParsedDep } from "./deps/parsers/npm";

export interface DepsScanOptions {
  ignoreDirs?: string[];
  /** Files larger than this (bytes) are skipped, and reported as a coverage gap. */
  maxFileBytes?: number;
  /** Maximum directory entries examined before stopping (bounds a hostile repo). */
  maxEntries?: number;
  /** Maximum total manifest bytes read before stopping. */
  maxTotalBytes?: number;
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
const DEFAULT_MAX_ENTRIES = 500_000;
const DEFAULT_MAX_TOTAL_BYTES = 300_000_000;
/** How many paths a coverage finding names; the rest are counted only. */
const MAX_NAMED_PATHS = 10;

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
    ruleId: depsRuleId(entry),
    severity: a.severity,
    category: "deps",
    title: `${entry.name} (${dep.ecosystem}): ${entry.reason}`,
    evidence: `${dep.manifestPath}:${dep.name}@${versionLabel}`,
    location: { path: dep.manifestPath },
    pq_status: a.pq_status,
    confidence: a.confidence,
    recommendation: a.recommendation,
    dependency: { ecosystem: dep.ecosystem, name: dep.name, ...(dep.version ? { version: dep.version } : {}) },
    // Entry-specific provenance first, then the generic standards for the
    // assessed posture (so a library at or above its `fixedIn`, now
    // transitional, keeps FIPS 203).
    references: dedupeByLabel([...(entry.references ?? []), ...referencesFor(a.pq_status)]),
  };
}

/**
 * The registry key for a dependency: PyPI names per PEP 503, crates.io names
 * with `_` and `-` equivalent (as crates.io treats them), npm names verbatim.
 */
function canonicalName(dep: ParsedDep): string {
  if (dep.ecosystem === "python") return normalizePythonName(dep.name);
  if (dep.ecosystem === "cargo") return dep.name.toLowerCase().replace(/_/g, "-");
  return dep.name;
}

/** Pure helper: map parsed deps against the registry into Findings. */
export function matchDeps(deps: readonly ParsedDep[], ids: IdAllocator = new IdAllocator()): Finding[] {
  const out: Finding[] = [];
  const seenEvidence = new Set<string>();
  for (const dep of deps) {
    const entry = lookupEntry(canonicalName(dep), dep.ecosystem);
    if (!entry) continue;
    const finding = toFinding(dep, entry, ids);
    if (seenEvidence.has(finding.evidence)) continue;
    seenEvidence.add(finding.evidence);
    out.push(finding);
  }
  return out;
}

type ManifestKind =
  | "package.json"
  | "package-lock"
  | "pnpm-lock"
  | "yarn-lock"
  | "requirements"
  | "pyproject"
  | "python-lock"
  | "pipfile"
  | "pipfile-lock"
  | "cargo-toml"
  | "cargo-lock";

interface ManifestHit {
  ecosystem: Ecosystem;
  kind: ManifestKind;
  absPath: string;
  manifestPath: string;
}

const MANIFESTS: ReadonlyMap<string, ManifestKind> = new Map([
  ["package.json", "package.json"],
  ["package-lock.json", "package-lock"],
  ["npm-shrinkwrap.json", "package-lock"],
  ["pnpm-lock.yaml", "pnpm-lock"],
  ["yarn.lock", "yarn-lock"],
  ["pyproject.toml", "pyproject"],
  ["poetry.lock", "python-lock"],
  ["uv.lock", "python-lock"],
  ["Pipfile", "pipfile"],
  ["Pipfile.lock", "pipfile-lock"],
  ["Cargo.toml", "cargo-toml"],
  ["Cargo.lock", "cargo-lock"],
]);

/**
 * Dependency files in formats cryptosweep does not parse. Finding one is
 * reported, so a Go, JVM or Ruby service is never mistaken for a clean one.
 */
const UNSUPPORTED_MANIFESTS: ReadonlySet<string> = new Set([
  "go.mod",
  "go.sum",
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
  "gradle.lockfile",
  "build.sbt",
  "Gemfile",
  "Gemfile.lock",
  "composer.json",
  "composer.lock",
  "packages.config",
  "packages.lock.json",
  "Directory.Packages.props",
  "setup.py",
  "setup.cfg",
  "environment.yml",
  "conda-lock.yml",
  "bun.lock",
  "bun.lockb",
  "deno.json",
  "deno.lock",
  "Package.swift",
  "Package.resolved",
  "Podfile.lock",
  "pubspec.yaml",
  "pubspec.lock",
  "mix.exs",
  "mix.lock",
  "vcpkg.json",
  "conanfile.txt",
  "conanfile.py",
]);

const UNSUPPORTED_EXTENSIONS = /\.(?:csproj|fsproj|vbproj|cabal|gemspec|nuspec)$/;

/** `requirements.txt`, `requirements-dev.txt`, `dev-requirements.in`, `constraints.txt`, `requirements/base.txt`. */
function isRequirementsFile(filename: string, parentDir: string): boolean {
  const lower = filename.toLowerCase();
  if (!lower.endsWith(".txt") && !lower.endsWith(".in")) return false;
  return lower.includes("requirements") || lower.includes("constraints") || parentDir === "requirements";
}

function classifyManifest(filename: string, parentDir: string): ManifestKind | null {
  return MANIFESTS.get(filename) ?? (isRequirementsFile(filename, parentDir) ? "requirements" : null);
}

function isUnsupportedManifest(filename: string): boolean {
  return UNSUPPORTED_MANIFESTS.has(filename) || UNSUPPORTED_EXTENSIONS.test(filename);
}

function ecosystemFor(kind: ManifestKind): Ecosystem {
  switch (kind) {
    case "package.json":
    case "package-lock":
    case "pnpm-lock":
    case "yarn-lock":
      return "npm";
    case "cargo-toml":
    case "cargo-lock":
      return "cargo";
    default:
      return "python";
  }
}

/** A bounded sample of paths for a coverage finding. */
interface PathSample {
  count: number;
  names: string[];
}

function record(sample: PathSample, relPath: string): void {
  sample.count += 1;
  if (sample.names.length < MAX_NAMED_PATHS) sample.names.push(relPath);
}

function describeSample(sample: PathSample): string {
  const more = sample.count - sample.names.length;
  const named = sample.names.join(", ");
  return more > 0 ? `${named}, and ${more} more` : named;
}

interface DepsWalk {
  readonly rootDir: string;
  readonly ignoreDirs: ReadonlySet<string>;
  readonly maxFileBytes: number;
  readonly hits: ManifestHit[];
  entries: number;
  bytes: number;
  truncated: boolean;
  readonly unsupported: PathSample;
  readonly tooLarge: PathSample;
}

/** Repository-relative, forward-slash path. */
function toRelative(rootDir: string, full: string): string {
  return relative(rootDir, full).split(sep).join("/");
}

function byName(a: Dirent, z: Dirent): number {
  return a.name < z.name ? -1 : a.name > z.name ? 1 : 0;
}

async function listDirectory(dir: string, walk: DepsWalk): Promise<Dirent[]> {
  const entries: Dirent[] = [];
  for await (const entry of await opendir(dir)) {
    if (walk.entries <= 0) {
      walk.truncated = true;
      break;
    }
    walk.entries -= 1;
    entries.push(entry);
  }
  return entries.sort(byName);
}

async function findManifests(dir: string, walk: DepsWalk): Promise<void> {
  let entries: Dirent[];
  try {
    entries = await listDirectory(dir, walk);
  } catch {
    return; // unreadable directories are reported by the source walk over the same tree
  }
  const parentDir = dir === walk.rootDir ? "" : (dir.split(sep).pop() ?? "");
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!walk.ignoreDirs.has(entry.name)) await findManifests(full, walk);
      continue;
    }
    if (!entry.isFile()) continue;
    const manifestPath = toRelative(walk.rootDir, full);
    const kind = classifyManifest(entry.name, parentDir);
    if (kind) walk.hits.push({ kind, ecosystem: ecosystemFor(kind), absPath: full, manifestPath });
    else if (isUnsupportedManifest(entry.name)) record(walk.unsupported, manifestPath);
  }
}

/** Open without following a swapped-in symlink or blocking on a FIFO (POSIX-only flags, zero elsewhere). */
const OPEN_FLAGS = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);

async function readBounded(handle: FileHandle, size: number): Promise<Buffer> {
  const buffer = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const { bytesRead } = await handle.read(buffer, offset, size - offset, offset);
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  return buffer.subarray(0, offset);
}

/**
 * Read a manifest, checking its size on the open handle first: the old
 * readFile-then-compare buffered a 1.5 GB sparse file before rejecting it.
 */
async function readManifest(hit: ManifestHit, walk: DepsWalk): Promise<string | null> {
  let handle: FileHandle;
  try {
    handle = await open(hit.absPath, OPEN_FLAGS);
  } catch {
    return null;
  }
  try {
    const info = await handle.stat();
    if (!info.isFile()) return null;
    if (info.size > walk.maxFileBytes) {
      record(walk.tooLarge, hit.manifestPath);
      return null;
    }
    if (info.size > walk.bytes) {
      walk.truncated = true;
      return null;
    }
    const buffer = await readBounded(handle, info.size);
    walk.bytes -= buffer.byteLength;
    return buffer.toString("utf8");
  } catch {
    return null;
  } finally {
    await handle.close().catch(() => undefined);
  }
}

function parseManifest(hit: ManifestHit, content: string): ParsedDep[] {
  switch (hit.kind) {
    case "package.json":
      return parsePackageJson(content, hit.manifestPath);
    case "package-lock":
      return parsePackageLock(content, hit.manifestPath);
    case "pnpm-lock":
      return parsePnpmLock(content, hit.manifestPath);
    case "yarn-lock":
      return parseYarnLock(content, hit.manifestPath);
    case "requirements":
      return parseRequirementsTxt(content, hit.manifestPath);
    case "pyproject":
      return parsePyproject(content, hit.manifestPath);
    case "python-lock":
      return parsePythonLock(content, hit.manifestPath);
    case "pipfile":
      return parsePipfile(content, hit.manifestPath);
    case "pipfile-lock":
      return parsePipfileLock(content, hit.manifestPath);
    case "cargo-toml":
      return parseCargoToml(content, hit.manifestPath);
    case "cargo-lock":
      return parseCargoLock(content, hit.manifestPath);
  }
}

function coverageFinding(n: number, ruleId: string, title: string, evidence: string, recommendation: string): Finding {
  return {
    id: `CSW-DEPCOV-${String(n).padStart(3, "0")}`,
    ruleId,
    severity: "info",
    category: "deps",
    title,
    evidence,
    pq_status: "unknown",
    confidence: "confirmed",
    recommendation,
  };
}

function coverageFindings(walk: DepsWalk): Finding[] {
  const out: Finding[] = [];
  if (walk.unsupported.count > 0) {
    out.push(
      coverageFinding(
        out.length + 1,
        "deps/unsupported-manifest",
        `${walk.unsupported.count} dependency file(s) in formats cryptosweep does not parse, coverage is incomplete`,
        describeSample(walk.unsupported),
        "These dependencies were not checked against the registry (supported: package.json, package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock, requirements*.txt, pyproject.toml, poetry.lock, uv.lock, Pipfile, Pipfile.lock, Cargo.toml, Cargo.lock). Review their crypto libraries by hand.",
      ),
    );
  }
  if (walk.tooLarge.count > 0) {
    out.push(
      coverageFinding(
        out.length + 1,
        "deps/manifest-too-large",
        `${walk.tooLarge.count} manifest(s) above the ${Math.round(walk.maxFileBytes / 100_000) / 10} MB limit were not parsed, coverage is incomplete`,
        describeSample(walk.tooLarge),
        "Raise maxFileBytes for the dependency scan, or review these manifests separately.",
      ),
    );
  }
  if (walk.truncated) {
    out.push(
      coverageFinding(
        out.length + 1,
        "deps/scan-truncated",
        "Dependency scan stopped at a resource limit, coverage is incomplete",
        "entry or byte budget reached",
        "Some manifests were not found or read. Raise maxEntries/maxTotalBytes or scan subdirectories individually.",
      ),
    );
  }
  return out;
}

/** Walk `rootDir`, parse every recognised manifest, return aggregated Findings. */
export async function scanDeps(rootDir: string, options: DepsScanOptions = {}): Promise<Finding[]> {
  const walk: DepsWalk = {
    rootDir,
    ignoreDirs: new Set([...DEFAULT_IGNORE_DIRS, ...(options.ignoreDirs ?? [])]),
    maxFileBytes: options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES,
    hits: [],
    entries: options.maxEntries ?? DEFAULT_MAX_ENTRIES,
    bytes: options.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES,
    truncated: false,
    unsupported: { count: 0, names: [] },
    tooLarge: { count: 0, names: [] },
  };
  await findManifests(rootDir, walk);
  const allDeps: ParsedDep[] = [];
  for (const hit of walk.hits) {
    const content = await readManifest(hit, walk);
    if (content !== null) allDeps.push(...parseManifest(hit, content));
  }
  const matched = matchDeps(allDeps);
  const findings = options.advisories?.enabled ? await annotateWithAdvisories(matched, allDeps, options.advisories) : matched;
  return [...findings, ...coverageFindings(walk)];
}
