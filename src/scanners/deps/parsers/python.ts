/**
 * Python-ecosystem dependency parsers.
 *
 * Handles `requirements.txt`-style files (PEP 508 lines), `pyproject.toml`
 * (PEP 621 `[project]` dependencies and optional-dependencies, PEP 735
 * `[dependency-groups]`, Poetry's `[tool.poetry]` dependencies, dev-dependencies
 * and groups, PDM and uv dev-dependencies), the `poetry.lock` / `uv.lock`
 * lockfiles, `Pipfile` and `Pipfile.lock`. Every name is normalised per PEP 503,
 * so `python_jose` and `PyJWT` match the registry's `python-jose` and `pyjwt`.
 * Pure / no I/O.
 */
import type { ParsedDep } from "./npm";
import { arrayOf, isTable, parseToml, stringOf, stringsOf, tableOf } from "./toml";
import type { TomlTable, TomlValue } from "./toml";

const PEP508_NAME = /^([A-Za-z0-9][A-Za-z0-9._-]*)/;
const VERSION_OP = /(===|==|~=|>=|<=|!=|>|<)/;

/** PEP 503 name normalisation: runs of `-`, `_` and `.` become one `-`, lower-cased. */
export function normalizePythonName(name: string): string {
  return name.replace(/[-_.]+/g, "-").toLowerCase();
}

/**
 * Cut a trailing `# comment`: a `#` at the start or after whitespace (a URL
 * fragment such as `#egg=` has none). A linear scan; the old `split(/\s+#/)`
 * backtracked quadratically over a long run of spaces.
 */
function stripComment(spec: string): string {
  for (let i = spec.indexOf("#"); i !== -1; i = spec.indexOf("#", i + 1)) {
    const before = spec.charCodeAt(i - 1);
    if (i === 0 || before === 0x20 || before === 0x09) return spec.slice(0, i);
  }
  return spec;
}

/** Drop the first `[extras]` group, found with indexOf so a run of `[` stays linear. */
function stripExtras(spec: string): string {
  const open = spec.indexOf("[");
  if (open < 0) return spec;
  const close = spec.indexOf("]", open);
  return close < 0 ? spec : spec.slice(0, open) + spec.slice(close + 1);
}

/** The version text after the first comparison operator (`==2.8.0` gives `2.8.0`), or "". */
function versionAfterOperator(spec: string): string {
  const opMatch = spec.match(VERSION_OP);
  if (!opMatch || opMatch.index === undefined) return "";
  return spec.slice(opMatch.index + opMatch[0].length).trim();
}

/**
 * Cut per-requirement options (`--hash=sha256:...`, `--config-settings ...`)
 * off a requirements line: they start at the first ` --`.
 */
function stripOptions(spec: string): string {
  const option = spec.search(/\s--/);
  return option < 0 ? spec : spec.slice(0, option);
}

function splitNameVersion(spec: string): { name: string; version: string; constraint: string } | null {
  const trimmed = spec.trim();
  if (!trimmed || trimmed.startsWith("#")) return null;
  // Strip line comments after the spec (`pkg==1.0  # comment`).
  const noComment = stripOptions(stripComment(trimmed)).trim();
  if (!noComment) return null;
  // Strip extras: `pkg[extra1,extra2]==1.0`.
  const noExtras = stripExtras(noComment);
  // Strip environment markers: `pkg==1.0 ; python_version < "3.11"`.
  const noMarker = noExtras.split(";")[0]?.trim() ?? "";
  if (!noMarker) return null;

  const nameMatch = noMarker.match(PEP508_NAME);
  if (!nameMatch) return null;
  const name = normalizePythonName(nameMatch[1] ?? "");
  const rest = noMarker.slice(nameMatch[0].length).trim();
  return { name, version: rest ? versionAfterOperator(rest) : "", constraint: rest };
}

/** Collects dependencies, one per normalised name (first occurrence wins). */
class DepList {
  private readonly seen = new Set<string>();
  readonly deps: ParsedDep[] = [];

  constructor(private readonly manifestPath: string) {}

  add(name: string, version: string, constraint?: string): void {
    const normalized = normalizePythonName(name);
    if (!normalized || this.seen.has(normalized)) return;
    this.seen.add(normalized);
    this.deps.push({
      name: normalized,
      version,
      ecosystem: "python",
      manifestPath: this.manifestPath,
      ...(constraint && constraint !== version ? { constraint } : {}),
    });
  }

  addSpec(spec: string): void {
    const split = splitNameVersion(spec);
    if (split) this.add(split.name, split.version, split.constraint);
  }
}

/**
 * Join pip's backslash line continuations, so `paramiko==3.4.0 \` followed
 * by `--hash=...` lines is one requirement, not a version ending in `\`.
 */
function logicalLines(content: string): string[] {
  const lines: string[] = [];
  let pending = "";
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trimEnd();
    if (line.endsWith("\\")) {
      pending += `${line.slice(0, -1)} `;
      continue;
    }
    lines.push(pending + line);
    pending = "";
  }
  if (pending) lines.push(pending);
  return lines;
}

/**
 * Parse a `requirements.txt`-style file (one PEP 508 spec per logical line).
 * Options (`-r`, `-e`, `--hash`) are skipped.
 */
export function parseRequirementsTxt(content: string, manifestPath: string): ParsedDep[] {
  const list = new DepList(manifestPath);
  for (const logical of logicalLines(content)) {
    const line = logical.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    list.addSpec(line);
  }
  return list.deps;
}

function tableValues(value: TomlValue | undefined): TomlValue[] {
  const table = tableOf(value);
  return table ? Object.values(table).filter((v): v is TomlValue => v !== undefined) : [];
}

/**
 * The version of a Poetry / Pipfile dependency value: `"^2.8"`, `{ version =
 * "^2.8", extras = [...] }`, or a list of such tables (multiple constraints).
 * Git, path and URL dependencies have none.
 */
function tableVersion(value: TomlValue): string {
  if (typeof value === "string") return value === "*" ? "" : value;
  if (isTable(value)) return stringOf(value.version) ?? "";
  const first = arrayOf(value).find(isTable);
  return first ? (stringOf(first.version) ?? "") : "";
}

function addTableDeps(list: DepList, table: TomlTable | null, versionOf: (value: TomlValue) => string): void {
  if (!table) return;
  for (const [name, value] of Object.entries(table)) {
    if (value === undefined || name.toLowerCase() === "python") continue;
    list.add(name, versionOf(value));
  }
}

/** Parse a `pyproject.toml`: PEP 621, PEP 735, Poetry, PDM and uv dependency tables. */
export function parsePyproject(content: string, manifestPath: string): ParsedDep[] {
  const doc = parseToml(content);
  const list = new DepList(manifestPath);
  const project = tableOf(doc.project);
  const tool = tableOf(doc.tool);

  for (const spec of stringsOf(project?.dependencies)) list.addSpec(spec);
  for (const group of tableValues(project?.["optional-dependencies"])) for (const spec of stringsOf(group)) list.addSpec(spec);
  // PEP 735: `{ include-group = "..." }` entries are tables and are skipped.
  for (const group of tableValues(doc["dependency-groups"])) for (const spec of stringsOf(group)) list.addSpec(spec);
  for (const group of tableValues(tableOf(tool?.pdm)?.["dev-dependencies"])) for (const spec of stringsOf(group)) list.addSpec(spec);
  for (const spec of stringsOf(tableOf(tool?.uv)?.["dev-dependencies"])) list.addSpec(spec);

  const poetry = tableOf(tool?.poetry);
  addTableDeps(list, tableOf(poetry?.dependencies), tableVersion);
  addTableDeps(list, tableOf(poetry?.["dev-dependencies"]), tableVersion);
  for (const group of tableValues(poetry?.group)) addTableDeps(list, tableOf(tableOf(group)?.dependencies), tableVersion);
  return list.deps;
}

/**
 * Parse a `poetry.lock` or `uv.lock`: both list every resolved package, direct
 * and transitive, as `[[package]]` tables with `name` and `version`.
 */
export function parsePythonLock(content: string, manifestPath: string): ParsedDep[] {
  const list = new DepList(manifestPath);
  for (const entry of arrayOf(parseToml(content).package)) {
    const pkg = tableOf(entry);
    const name = stringOf(pkg?.name);
    if (name) list.add(name, stringOf(pkg?.version) ?? "");
  }
  return list.deps;
}

/** Parse a `Pipfile` (`[packages]` and `[dev-packages]`). */
export function parsePipfile(content: string, manifestPath: string): ParsedDep[] {
  const doc = parseToml(content);
  const list = new DepList(manifestPath);
  for (const section of [doc.packages, doc["dev-packages"]]) {
    for (const [name, value] of Object.entries(tableOf(section) ?? {})) {
      if (value === undefined || name.toLowerCase() === "python") continue;
      const declared = tableVersion(value);
      list.add(name, versionAfterOperator(declared) || declared, declared);
    }
  }
  return list.deps;
}

/** Parse a `Pipfile.lock` (JSON: `default` and `develop` maps of pinned versions). */
export function parsePipfileLock(content: string, manifestPath: string): ParsedDep[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }
  const list = new DepList(manifestPath);
  if (parsed === null || typeof parsed !== "object") return list.deps;
  for (const section of ["default", "develop"]) {
    const packages = (parsed as Record<string, unknown>)[section];
    if (packages === null || typeof packages !== "object") continue;
    for (const [name, entry] of Object.entries(packages as Record<string, unknown>)) {
      const version = entry !== null && typeof entry === "object" ? (entry as Record<string, unknown>).version : undefined;
      list.add(name, typeof version === "string" ? versionAfterOperator(version) || version : "", typeof version === "string" ? version : undefined);
    }
  }
  return list.deps;
}
