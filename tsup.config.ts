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
});
