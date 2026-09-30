import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * Lean-runtime invariant. The AST scanner uses @babel/parser, but only as a
 * devDependency that tsup inlines into the bundle at build time. The published
 * package must keep exactly one runtime dependency, so a future edit that leaks
 * @babel/* (or anything else) into `dependencies` fails here rather than silently
 * expanding every user's install graph.
 */
describe("package invariants", () => {
  const pkg = JSON.parse(
    readFileSync(fileURLToPath(new URL("../package.json", import.meta.url)), "utf8"),
  ) as { dependencies: Record<string, string>; engines?: { node?: string } };

  it("has exactly one runtime dependency (cac)", () => {
    expect(Object.keys(pkg.dependencies)).toEqual(["cac"]);
  });

  it("targets Node >= 22, the oldest line CI runs (the parser stays pinned to Babel 7.x)", () => {
    expect(pkg.engines?.node).toMatch(/>=\s*22/);
  });
});
