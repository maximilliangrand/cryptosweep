import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { VERSION } from "../src/version";

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
  ) as { version: string; dependencies: Record<string, string>; engines?: { node?: string } };

  it("has exactly one runtime dependency (cac)", () => {
    expect(Object.keys(pkg.dependencies)).toEqual(["cac"]);
  });

  it("reports one version everywhere: package.json, the CLI/SARIF VERSION and the Urfael manifest", () => {
    const plugin = JSON.parse(
      readFileSync(fileURLToPath(new URL("../integrations/urfael/plugin.json", import.meta.url)), "utf8"),
    ) as { version: string; author: string; provenance: { sourceUrl: string } };
    expect(VERSION).toBe(pkg.version);
    expect(plugin.version).toBe(pkg.version);
    expect(plugin.provenance.sourceUrl).toBe("https://github.com/maximilliangrand/cryptosweep");
  });

  it("targets Node >= 22.20, the first 22.x release whose builds ship OpenSSL 3.5 (the parser stays pinned to Babel 7.x)", () => {
    // Node 22.0 to 22.19 ship OpenSSL 3.0, which has no ML-KEM TLS groups: the
    // post-quantum probe cannot run there, and an ML-KEM-only server refuses every handshake.
    expect(pkg.engines?.node).toBe(">=22.20");
  });
});
