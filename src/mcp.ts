#!/usr/bin/env node
/**
 * cryptosweep-mcp: the stdio entry point.
 *
 * This file is only ever executed, never imported, so it runs the server
 * unconditionally. An "am I the main module?" check comparing `process.argv[1]`
 * with `import.meta.url` fails whenever the bin is reached through a symlink
 * (npm and pnpm bin shims, macOS `/tmp`), and the server then exited silently.
 * The protocol, tools and lifecycle live in `./mcp-server`, which has no side
 * effects, so tests and embedders import that module instead.
 */
import { serve } from "./mcp-server";

serve(process.stdin, process.stdout).then(
  () => process.exit(0),
  (err: unknown) => {
    process.stderr.write(`cryptosweep-mcp: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  },
);
