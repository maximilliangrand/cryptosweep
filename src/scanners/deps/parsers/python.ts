/**
 * Python-ecosystem dependency parsers.
 *
 * Handles `requirements.txt` (PEP 508 lines) and `pyproject.toml`'s PEP 621
 * `[project]` table (`dependencies` + `optional-dependencies`). Pure / no I/O.
 */
import type { ParsedDep } from "./npm";

const PEP508_NAME = /^([A-Za-z0-9][A-Za-z0-9._-]*)/;
const VERSION_OP = /(==|~=|>=|<=|!=|>|<|===)/;

function splitNameVersion(spec: string): { name: string; version: string } | null {
  const trimmed = spec.trim();
  if (!trimmed || trimmed.startsWith("#")) return null;
  // Strip line comments after the spec (`pkg==1.0  # comment`).
  const noComment = trimmed.split(/\s+#/)[0]?.trim() ?? "";
  if (!noComment) return null;
  // Strip extras: `pkg[extra1,extra2]==1.0`.
  const noExtras = noComment.replace(/\[[^\]]*\]/, "");
  // Strip environment markers: `pkg==1.0 ; python_version < "3.11"`.
  const noMarker = noExtras.split(";")[0]?.trim() ?? "";
  if (!noMarker) return null;

  const nameMatch = noMarker.match(PEP508_NAME);
  if (!nameMatch) return null;
  const name = (nameMatch[1] ?? "").toLowerCase();
  const rest = noMarker.slice(nameMatch[0].length).trim();
  if (!rest) return { name, version: "" };
  const opMatch = rest.match(VERSION_OP);
  if (!opMatch || opMatch.index === undefined) return { name, version: "" };
  const version = rest.slice(opMatch.index + opMatch[0].length).trim();
  return { name, version };
}

/** Parse a `requirements.txt`-style file (one PEP 508 spec per line). */
export function parseRequirementsTxt(content: string, manifestPath: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  const seen = new Set<string>();
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    const split = splitNameVersion(line);
    if (!split || seen.has(split.name)) continue;
    seen.add(split.name);
    deps.push({ name: split.name, version: split.version, ecosystem: "python", manifestPath });
  }
  return deps;
}

function extractProjectDepsArray(content: string): string[] {
  // Find the [project] table header and slice until the next top-level table.
  const projectIdx = content.search(/^\[project\]\s*$/m);
  if (projectIdx < 0) return [];
  const after = content.slice(projectIdx);
  const nextTable = after.slice(1).search(/^\[[^\]]+\]\s*$/m);
  const projectBlock = nextTable < 0 ? after : after.slice(0, 1 + nextTable);

  const specs: string[] = [];
  // Top-level `dependencies = [...]`.
  const depsArray = /^dependencies\s*=\s*\[([\s\S]*?)\]/m.exec(projectBlock);
  if (depsArray?.[1]) specs.push(...extractQuotedStrings(depsArray[1]));
  // Each value of `[project.optional-dependencies]` group (PEP 621).
  return specs;
}

function extractQuotedStrings(block: string): string[] {
  const out: string[] = [];
  const re = /["']([^"'\n]+)["']/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(block)) !== null) {
    if (m[1]) out.push(m[1]);
  }
  return out;
}

function extractOptionalDeps(content: string): string[] {
  const idx = content.search(/^\[project\.optional-dependencies\]\s*$/m);
  if (idx < 0) return [];
  const after = content.slice(idx);
  const nextTable = after.slice(1).search(/^\[[^\]]+\]\s*$/m);
  const block = nextTable < 0 ? after : after.slice(0, 1 + nextTable);
  return extractQuotedStrings(block);
}

/** Parse a `pyproject.toml`. Reads PEP 621 `[project]` deps; ignores tool-specific tables. */
export function parsePyproject(content: string, manifestPath: string): ParsedDep[] {
  const specs = [...extractProjectDepsArray(content), ...extractOptionalDeps(content)];
  const deps: ParsedDep[] = [];
  const seen = new Set<string>();
  for (const spec of specs) {
    const split = splitNameVersion(spec);
    if (!split || seen.has(split.name)) continue;
    seen.add(split.name);
    deps.push({ name: split.name, version: split.version, ecosystem: "python", manifestPath });
  }
  return deps;
}
