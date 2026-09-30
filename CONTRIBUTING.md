# Contributing to cryptosweep

Thanks for helping make the post-quantum migration legible. This project has one
guiding principle, and most review feedback traces back to it:

> **Parse, do not guess.** A finding is only as good as the evidence behind it. If
> the scanner cannot be sure, it says so with a `confidence` level rather than
> asserting.

## Getting set up

Requires Node >= 20 and pnpm.

```bash
pnpm install
pnpm build
```

Four gates must pass before anything merges. Run them locally:

```bash
pnpm typecheck   # tsc --noEmit, strict
pnpm lint        # eslint
pnpm test        # vitest, offline (no network in unit tests)
pnpm build       # tsup
```

## Where things live

- `src/asn1.ts`, `src/crypto.ts`: the parsing and classification core. Changes here
  need real-input tests (see `tests/fixtures/certs/`, generated with OpenSSL).
- `src/scanners/`: the TLS, source, and dependency scanners.
- `src/output/`: JSON, Markdown, CBOM, SARIF, and HTML projections of one `Finding`
  model. New output formats go here and read only from that model.
- `src/report.ts`: the `Finding` ontology. Add fields here, not per-scanner.

## Adding a library to the dependency registry

This is the most common and welcome contribution. Edit `src/scanners/deps/registry.ts`.
Every entry must:

1. Cite a source in the `reason` (a maintainer changelog, an advisory, or NIST/CNSA
   guidance). No entry without evidence.
2. Set `pq_status` and `severity` honestly. A library that is classical by nature at
   every version has no `fixedIn`. A library whose PQ-relevant support arrived in a
   specific release records that release in `fixedIn` so patched installs are not
   flagged as vulnerable.
3. Keep `(name, ecosystem)` unique. The registry sanity test enforces this.

## Tests

- Unit tests must be **offline and deterministic**. Network access belongs behind an
  injectable probe (see how `scanTls` takes a `probe`).
- New detection logic needs both a positive case and a false-positive guard.
- Certificate fixtures are generated with a real OpenSSL (3.x) so that key type and
  signature OID are authentic, not hand-assembled bytes.

## Style

- No em dashes or en dashes in prose (use commas, colons, or parentheses). Real CLI
  flags like `--fail-on` are of course fine.
- Match the surrounding code: small pure functions, dependency injection for I/O,
  explicit types, no bare `any`.

## Reporting a security issue

The scanner ingests untrusted input (arbitrary hosts, repositories, and, through
the MCP server, tool arguments written by a model). If you find a way to make it reach an internal address, execute code, or
exhaust resources, please open a private report rather than a public issue.
