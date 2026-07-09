import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/cli.ts", "src/index.ts"],
  format: ["esm", "cjs"],
  target: "node20",
  platform: "node",
  clean: true,
  dts: { entry: "src/index.ts" },
  sourcemap: true,
  splitting: false,
  shims: false,
  // @babel/parser is a devDependency inlined at build time (it is the AST
  // scanner's parser). Minify to bound the vendored size; do NOT add it to
  // `external`, or the AST scanner would break at runtime.
  minify: true,
});
