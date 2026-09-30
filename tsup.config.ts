import { defineConfig } from "tsup";
import type { Options } from "tsup";

const shared: Options = {
  target: "node20",
  platform: "node",
  sourcemap: true,
  splitting: false,
  shims: false,
  // @babel/parser is a devDependency inlined at build time (it is the AST
  // scanner's parser). Minify to bound the vendored size; do NOT add it to
  // `external`, or the AST scanner would break at runtime.
  minify: true,
};

// The two builds run concurrently and share dist/, so each one's clean step
// keeps the other's outputs (tsup always removes everything else first).
export default defineConfig([
  {
    ...shared,
    // The bins are executed, never require()d, so they ship as ESM only. A CJS
    // build of an entry that reads import.meta.url cannot run at all.
    entry: ["src/cli.ts", "src/mcp.ts"],
    format: ["esm"],
    clean: ["!index.*"],
  },
  {
    ...shared,
    entry: ["src/index.ts"],
    format: ["esm", "cjs"],
    dts: { entry: "src/index.ts" },
    clean: ["!cli.*", "!mcp.*"],
  },
]);
