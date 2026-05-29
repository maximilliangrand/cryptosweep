import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    globals: false,
  },
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        compatibilityDate: "2026-05-01",
        d1Databases: ["DB"],
        kvNamespaces: ["RL_KV"],
        bindings: {
          NODE_ENV: "test",
          IP_HASH_SECRET: "test-secret-not-for-prod",
        },
      },
    }),
  ],
});
