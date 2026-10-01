/**
 * Cargo (Rust) dependency parsers.
 *
 * `Cargo.toml`: `[dependencies]`, `[dev-dependencies]` and `[build-dependencies]`
 * in every form Cargo accepts (`name = "1.0"`, inline tables, dotted
 * `[dependencies.name]` tables), target-specific tables
 * (`[target.'cfg(unix)'.dependencies]`), `[workspace.dependencies]`, renamed
 * crates (`alias = { package = "ring", ... }`) and `name = { workspace = true }`
 * inheritance. `Cargo.lock`: every resolved `[[package]]`, direct and
 * transitive. Pure / no I/O.
 */
import type { ParsedDep } from "./npm";
import { arrayOf, parseToml, stringOf, tableOf } from "./toml";
import type { TomlTable, TomlValue } from "./toml";

const DEP_TABLES = ["dependencies", "dev-dependencies", "build-dependencies"] as const;

function versionOf(value: TomlValue | undefined): string {
  if (typeof value === "string") return value;
  return stringOf(tableOf(value)?.version) ?? "";
}

/** Parse a `Cargo.toml`. Returns one entry per declared crate across every dependency table. */
export function parseCargoToml(content: string, manifestPath: string): ParsedDep[] {
  const doc = parseToml(content);
  const workspace = tableOf(tableOf(doc.workspace)?.dependencies);
  const tables: TomlTable[] = [];
  for (const key of DEP_TABLES) {
    const table = tableOf(doc[key]);
    if (table) tables.push(table);
  }
  if (workspace) tables.push(workspace);
  for (const target of Object.values(tableOf(doc.target) ?? {})) {
    for (const key of DEP_TABLES) {
      const table = tableOf(tableOf(target)?.[key]);
      if (table) tables.push(table);
    }
  }

  const seen = new Set<string>();
  const deps: ParsedDep[] = [];
  for (const table of tables) {
    for (const [alias, value] of Object.entries(table)) {
      if (value === undefined) continue;
      const spec = tableOf(value);
      const name = stringOf(spec?.package) ?? alias;
      let version = versionOf(value);
      if (!version && spec?.workspace === true) version = versionOf(workspace?.[name] ?? workspace?.[alias]);
      if (seen.has(name)) continue;
      seen.add(name);
      // A bare Cargo.toml requirement is a caret requirement (`0.23` means `^0.23`).
      const constraint = /^\d/.test(version) ? `^${version}` : undefined;
      deps.push({ name, version, ecosystem: "cargo", manifestPath, ...(constraint ? { constraint } : {}) });
    }
  }
  return deps;
}

/** Parse a `Cargo.lock`: one entry per resolved `name@version`. */
export function parseCargoLock(content: string, manifestPath: string): ParsedDep[] {
  const seen = new Set<string>();
  const deps: ParsedDep[] = [];
  for (const entry of arrayOf(parseToml(content).package)) {
    const pkg = tableOf(entry);
    const name = stringOf(pkg?.name);
    const version = stringOf(pkg?.version) ?? "";
    if (!name || seen.has(`${name}@${version}`)) continue;
    seen.add(`${name}@${version}`);
    deps.push({ name, version, ecosystem: "cargo", manifestPath });
  }
  return deps;
}
