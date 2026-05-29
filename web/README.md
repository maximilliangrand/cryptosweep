# @cryptosweep/web

Cloudflare Worker that serves the cryptosweep landing page and captures scan
requests to D1. Manual fulfillment for v0.1 — every row in `scan_requests`
becomes a CLI run by hand.

## Layout

```
src/
  index.ts                # Worker entry — routes GET / and POST /api/scan-request
  landing.html            # Static HTML, bundled as text via wrangler [[rules]]
  env.ts                  # Env binding types
  api/scan-request.ts     # validate, rate-limit, write to D1
  lib/validate.ts         # email + domain validation, body parsing
  lib/rate-limit.ts       # KV-backed fixed-window counter (5 req / 60s)
  lib/ip-hash.ts          # HMAC-SHA-256 over the client IP
  storage/d1-schema.sql   # scan_requests table + indexes
tests/                    # vitest + @cloudflare/vitest-pool-workers
```

## Local dev

```bash
pnpm install
cp web/.dev.vars.example web/.dev.vars   # then fill IP_HASH_SECRET
pnpm --filter @cryptosweep/web db:apply:local
pnpm --filter @cryptosweep/web dev
```

Then visit `http://127.0.0.1:8787/`. POSTs to `/api/scan-request` write to the
local D1 file under `web/.wrangler/`.

## Quality gate

```bash
pnpm --filter @cryptosweep/web typecheck
pnpm --filter @cryptosweep/web lint
pnpm --filter @cryptosweep/web build      # wrangler dry-run, emits web/dist/
pnpm --filter @cryptosweep/web test       # vitest via miniflare
```

## Bindings

`wrangler.toml` declares two production bindings whose IDs are `TBD-MAX-WILL-PROVIDE`:

- `DB` — D1 database `cryptosweep_web_dev` (apply `src/storage/d1-schema.sql`)
- `RL_KV` — KV namespace for rate-limit counters

Fill these IDs from `wrangler d1 create` / `wrangler kv namespace create` before
deploying. The Worker has not been deployed; this branch ships dev config only.

## Inspecting captured requests

```bash
wrangler d1 execute cryptosweep_web_dev --local --command \
  "SELECT id, email, target, created_at, status FROM scan_requests ORDER BY created_at DESC LIMIT 20;"
```
