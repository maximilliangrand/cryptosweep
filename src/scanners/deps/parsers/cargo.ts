/**
 * Cargo (Rust) dependency parser.
 *
 * Reads `[dependencies]`, `[dev-dependencies]`, and `[build-dependencies]`
 * tables from a `Cargo.toml`. Supports both the short form (`name = "1.0"`)
 * and the inline-table form (`name = { version = "1.0", features = [...] }`).
 * Pure / no I/O.
 */
import type { ParsedDep } from "./npm";

const DEP_TABLES = ["dependencies", "dev-dependencies", "build-dependencies"] as const;

function findTableBlocks(content: string, tableName: string): string[] {
  const blocks: string[] = [];
  const headerRe = new RegExp(`^\\[${escapeRegex(tableName)}\\]\\s*$`, "gm");
  let m: RegExpExecArray | null;
  while ((m = headerRe.exec(content)) !== null) {
    const afterHeader = content.slice(m.index + m[0].length);
    const nextTable = afterHeader.search(/^\[[^\]]+\]\s*$/m);
    blocks.push(nextTable < 0 ? afterHeader : afterHeader.slice(0, nextTable));
  }
  return blocks;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function extractInlineTableVersion(value: string): string {
  // value is like `{ version = "1.0", features = ["..."] }` — possibly without `version` key.
  const versionMatch = /\bversion\s*=\s*["']([^"']+)["']/.exec(value);
  return versionMatch?.[1] ?? "";
}

function parseDepLine(line: string): { name: string; version: string } | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) return null;
  const eq = trimmed.indexOf("=");
  if (eq < 0) return null;
  const rawName = trimmed.slice(0, eq).trim();
  // Strip surrounding quotes if any (rare but legal).
  const name = rawName.replace(/^["']|["']$/g, "");
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(name)) return null;
  const valueRaw = trimmed.slice(eq + 1).trim();
  const stringMatch = /^["']([^"']+)["']/.exec(valueRaw);
  if (stringMatch?.[1]) return { name, version: stringMatch[1] };
  if (valueRaw.startsWith("{")) return { name, version: extractInlineTableVersion(valueRaw) };
  return { name, version: "" };
}

/** Parse a `Cargo.toml`. Returns one entry per direct dep across the supported tables. */
export function parseCargoToml(content: string, manifestPath: string): ParsedDep[] {
  const seen = new Set<string>();
  const deps: ParsedDep[] = [];
  for (const table of DEP_TABLES) {
    for (const block of findTableBlocks(content, table)) {
      for (const rawLine of block.split(/\r?\n/)) {
        const parsed = parseDepLine(rawLine);
        if (!parsed || seen.has(parsed.name)) continue;
        seen.add(parsed.name);
        deps.push({
          name: parsed.name,
          version: parsed.version,
          ecosystem: "cargo",
          manifestPath,
        });
      }
    }
  }
  return deps;
}
