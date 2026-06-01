# cryptosweep

A post-quantum (PQ) crypto migration scanner. `cryptosweep` inspects what a
system actually negotiates and ships — TLS certificates and source-code crypto —
and reports the primitives that a cryptographically-relevant quantum computer
would break (RSA, ECDSA/EdDSA, classical key exchange) so you can plan a
migration to hybrid / ML-KEM / ML-DSA.

This is the **v0.1 CLI + library**. It runs two scanners:

- **TLS posture** — certificate chain, leaf key type & size, signature
  algorithm, validity, negotiated TLS version, and a hybrid-KEX readiness hint
  (looks for `X25519MLKEM768`).
- **Source-code crypto** — a fast regex sweep for weak `node:crypto` usage
  (MD5/SHA-1, DES/3DES/RC4), `jsonwebtoken` algorithms, hardcoded private keys,
  and embedded PEM public keys.

## Install

Requires Node ≥ 20.

```bash
pnpm install
pnpm build
# run the built CLI
node dist/cli.js --help
```

## Usage

```bash
# TLS posture scan of a host (scheme/path are ignored)
cryptosweep scan https://www.example.com

# Source scan of a GitHub repo (shallow-cloned to a temp dir) ...
cryptosweep scan facebook/react
cryptosweep scan https://github.com/owner/repo.git

# ... or a local directory
cryptosweep scan ./path/to/project

# Write machine-readable output
cryptosweep scan https://www.example.com --out report.json --md report.md
```

Options for `scan`:

| Option | Description |
| --- | --- |
| `--out <file>` | Write the JSON report to `<file>` |
| `--md <file>` | Write the Markdown report to `<file>` |
| `--port <port>` | TLS port (defaults to 443 or the port in the target) |
| `--timeout <ms>` | TLS handshake timeout (default 10000) |

Other commands: `cryptosweep email`, `cryptosweep version`, `cryptosweep help`.

With no `--out`/`--md`, the Markdown report is printed to stdout.

### Emailing a report

`cryptosweep email` takes a previously-generated JSON report and sends it to a
recipient via [Resend](https://resend.com). HTML + plain-text bodies are
rendered locally; no SDK dependency.

```bash
cryptosweep email --report /tmp/csw-smoke.json --to lead@example.com
cryptosweep email --report /tmp/csw-smoke.json --to lead@example.com \
  --from scan@cryptosweep.com --subject "Your cryptosweep PQ readiness report"
```

| Option | Description |
| --- | --- |
| `--report <file>` | Path to a cryptosweep JSON report (from `scan --out`) |
| `--to <email>` | Recipient email address |
| `--from <email>` | Sender address (defaults to `$SCAN_FROM_EMAIL` or `scan@cryptosweep.com`) |
| `--subject <subject>` | Email subject (defaults to a per-target line) |

Required env var: `RESEND_API_KEY`. The `--from` domain must be verified in
your Resend dashboard.

### Fulfilling a scan request manually (v0.1 workflow)

The hosted landing page (`web/`) captures scan requests into D1 and pings
Discord on each new entry. v0.1 fulfilment is intentionally manual:

1. Discord ping arrives via webhook with the requester's email + target.
2. Generate the report:
   ```bash
   node dist/cli.js scan <target> --out /tmp/<id>.json
   ```
3. Email it:
   ```bash
   node dist/cli.js email --report /tmp/<id>.json --to <email>
   ```
4. Done — the recipient receives the report via Resend.

### Environment variables

| Var | Where | Description |
| --- | --- | --- |
| `RESEND_API_KEY` | CLI (`email`) | Required. Resend API key. |
| `SCAN_FROM_EMAIL` | CLI (`email`) | Optional. Sender address; defaults to `scan@cryptosweep.com`. Must be a verified Resend sender. |
| `DISCORD_WEBHOOK_URL` | Worker (`web/`) | Optional. Discord channel webhook fired on each successful `/api/scan-request`. Leave empty to disable. Set in prod with `wrangler secret put DISCORD_WEBHOOK_URL`. |

## Output format

A report is JSON (and a rendered Markdown summary):

```jsonc
{
  "target": "www.example.com",
  "scanned_at": "2026-05-27T12:00:00.000Z",
  "summary": { "findings": 3, "critical": 0, "high": 2, "medium": 1, "low": 0 },
  "findings": [
    {
      "id": "CSW-TLS-001",
      "severity": "high",
      "category": "tls",
      "title": "Leaf public key: RSA-2048",
      "evidence": "www.example.com:443 (www.example.com)",
      "pq_status": "vulnerable",
      "recommendation": "Plan migration to a post-quantum / hybrid certificate ..."
    }
  ]
}
```

- `severity`: `critical | high | medium | low | info`
- `category`: `tls | source | deps | jwt | keys`
- `pq_status`: `vulnerable | transitional | safe | unknown`

The same functions are available as a library:

```ts
import { scanTls, scanSource, buildReport, toJson } from "cryptosweep";

const findings = await scanTls("www.example.com");
process.stdout.write(toJson(buildReport("www.example.com", findings)));
```

## Roadmap

- **v0.1** (this release) — CLI, TLS posture scanner, source-code crypto scanner.
- **v0.2** — dependency-audit scanner and scanning whole public GitHub orgs.
- **v0.3** — hosted web app with shareable reports and migration recommendations.

## License

MIT — see [LICENSE](./LICENSE).
