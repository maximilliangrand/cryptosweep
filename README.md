# cryptosweep

**Post-quantum cryptography migration scanner for SaaS companies whose customer data has a multi-decade confidentiality horizon.**

Scans your public surface, your repos, and your dependencies to produce a board-readable PQ-readiness report — with NIST-aligned remediation for every finding.

---

## TL;DR

`cryptosweep` answers a question every CISO will be asked in 2027–2030:

> *"Are we ready for the post-quantum migration?"*

It inventories the cryptographic primitives a system actually uses (TLS certificates, source-code crypto patterns, dependency manifests) and flags the ones a cryptographically-relevant quantum computer would break — RSA, ECDSA, EdDSA, classical key exchange — so engineering teams can plan a migration to hybrid / ML-KEM / ML-DSA before they have to.

Detection is designed to be defensible, not heuristic where it counts: certificate keys are typed from a parsed `KeyObject`, signature algorithms from the certificate's actual ASN.1 field, and hybrid post-quantum key exchange (X25519MLKEM768) is confirmed by an active capability probe. Every finding carries a confidence level and a NIST/standards citation.

Runs as a Node CLI. Outputs JSON, Markdown, a **CycloneDX 1.6 CBOM**, **SARIF 2.1.0** (for CI / code scanning), and a **self-contained interactive HTML report**. A `--fail-on <severity>` gate makes it a CI check. Optional email delivery via Resend, and an optional hosted landing page (Cloudflare Worker) for capturing scan requests.

---

## Why this matters now

Three independent timelines are converging:

1. **NIST has standardized post-quantum primitives.** FIPS 203 (ML-KEM / Kyber), FIPS 204 (ML-DSA / Dilithium), and FIPS 205 (SLH-DSA / SPHINCS+) are final. There is no excuse left to ship only RSA / ECDSA in new systems.
2. **CNSA 2.0** mandates US federal systems migrate to PQC by ~2030–2035. Every Fortune 500 with federal contracts inherits that deadline. Banks, insurers, hospitals follow.
3. **"Harvest now, decrypt later"** attacks are real and already happening. Adversaries copy encrypted traffic *today* and decrypt it *when quantum computers arrive*. Any data with > 10-year confidentiality value — legal records, medical histories, M&A deals, IP filings — is already exposed.

Most SaaS today still ships RSA-2048 + ECDSA-P256 as TLS defaults. That posture is fine in 2026 and broken by 2035. Cryptosweep finds those primitives so they can be migrated on a deliberate schedule rather than during an emergency.

---

## Who this is for

**Primary ICP — mid-market legal SaaS** (Clio, Filevine, Smokeball, MyCase, PracticePanther tier; 50–500 employees).

Legal data is uniquely exposed to harvest-now-decrypt-later because:
- **30+ year confidentiality horizon** — privileged communications, divorces, criminal records, M&A deal rooms, IP.
- **ABA Model Rule 1.6(c)** imposes a *duty of technological competence* — including reasonable efforts to prevent unauthorized disclosure of client confidences.
- **Federal court systems** (PACER-NG) are moving to PQ-ready crypto; vendors will be required to follow.

**Secondary fits:**
- **Healthtech SaaS** — HIPAA + multi-decade record retention.
- **Fintech infrastructure** — PCI + emerging FFIEC PQ guidance.
- **Defense subcontractors** — directly bound by CNSA 2.0.
- **Anyone with long-lived encrypted backups** — encrypted-at-rest with classical KEKs is the obvious harvest target.

If your customer's data still matters in 2040, you are the user.

---

## What it scans

| Surface | Scanner | Examples |
|---|---|---|
| **Public TLS** | `tls` | Cert chain, leaf key type/size (from a parsed `KeyObject`), signature algorithm (from the ASN.1 field), and active hybrid-KEX (`X25519MLKEM768`) support probing |
| **Source code** | `source` | Weak `node:crypto` usage (MD5 / SHA-1 / DES / 3DES / RC4), `jsonwebtoken` algorithms, hardcoded RSA/EC private keys, embedded PEM public keys |
| **Dependencies** | `deps` | `package.json` / `pnpm-lock.yaml`, `requirements.txt` / `pyproject.toml`, `Cargo.toml` — flagged against an internal registry of PQ-vulnerable libs with NIST-aligned alternatives |

All three run automatically against a local directory or shallow-cloned GitHub repo. TLS-only mode runs against a hostname.

---

## Quick start

Requires Node ≥ 20 and pnpm.

```bash
git clone https://github.com/Grandillionaire/cryptosweep.git
cd cryptosweep
pnpm install
pnpm build

# TLS-only scan of a hostname
node dist/cli.js scan https://www.example.com

# Full scan of a GitHub repo (TLS + source + deps)
node dist/cli.js scan facebook/react

# Local directory, every output format at once
node dist/cli.js scan ./my-project \
  --out report.json --md report.md \
  --cbom cbom.json --sarif results.sarif --html report.html

# CI gate: exit non-zero if anything is high or worse
node dist/cli.js scan ./my-project --sarif results.sarif --fail-on high
```

Output goes to stdout as Markdown by default, or to any combination of the output flags below.

## Outputs & interoperability

| Flag | Format | Use |
|---|---|---|
| `--out` | JSON | The full report, machine-readable |
| `--md` | Markdown | Human-readable summary + recommendations |
| `--cbom` | **CycloneDX 1.6 CBOM** | Cryptography Bill of Materials — flows into SBOM / compliance tooling; each asset carries its NIST post-quantum security level |
| `--sarif` | **SARIF 2.1.0** | GitHub code scanning and any SARIF-aware CI, with `security-severity` per rule |
| `--html` | Self-contained HTML | Offline interactive report: filter by severity / PQ status, search, drill into evidence and citations |
| `--fail-on <sev>` | exit code | Exit `2` if any finding is at/above `critical\|high\|medium\|low\|info` |

Every finding also carries a `confidence` level (`confirmed` = parsed structure; `low` = a context-sensitive heuristic) so downstream consumers can triage.

---

## CLI reference

### `scan <target>`

`<target>` is one of:
- A hostname or URL (`example.com`, `https://example.com:8443/whatever`) — runs **TLS scanner only**.
- A GitHub shorthand or URL (`owner/repo`, `https://github.com/owner/repo`) — shallow-clones and runs **TLS (homepage) + source + deps**.
- A local directory — runs **source + deps**.

| Option | Description | Default |
|---|---|---|
| `--out <file>` | Write JSON report | (none) |
| `--md <file>` | Write Markdown report | (none) |
| `--port <port>` | TLS port | 443 (or as in URL) |
| `--timeout <ms>` | TLS handshake timeout | 10000 |

### `email`

Send a previously-generated JSON report via [Resend](https://resend.com). HTML + plain-text bodies are rendered locally; no SDK dependency.

```bash
cryptosweep email --report /tmp/report.json --to lead@example.com
```

| Option | Description |
|---|---|
| `--report <file>` | Path to a JSON report (from `scan --out`) |
| `--to <email>` | Recipient |
| `--from <email>` | Sender (defaults to `$SCAN_FROM_EMAIL` or `scan@cryptosweep.com`) |
| `--subject <s>` | Override subject |

Requires `RESEND_API_KEY`. The `--from` domain must be verified in your Resend dashboard.

### `version` · `help`

Standard.

---

## Sample output

Real scan of `www.filevine.com` (default Markdown output):

```text
# cryptosweep report

- Target:     https://www.filevine.com
- Findings:   5 (critical: 0, high: 2, medium: 1, low: 0, info: 2)

| Severity  | PQ status    | Confidence | Finding                                                          |
| --------- | ------------ | ---------- | ---------------------------------------------------------------- |
| 🟧 high   | vulnerable   | confirmed  | Leaf public key: ECDSA P-256                                     |
| 🟧 high   | vulnerable   | confirmed  | Leaf signature algorithm: ecdsaWithSHA256                       |
| 🟨 medium | vulnerable   | high       | Certificate chain has 3 intermediate(s) using classical crypto   |
| ⬜ info   | transitional | confirmed  | Negotiated TLSv1.3                                               |
| ⬜ info   | transitional | confirmed  | Server supports hybrid post-quantum key exchange (X25519MLKEM768)|
```

Note the last row: cryptosweep actively confirmed the server *will* negotiate
X25519MLKEM768 — the session key exchange already resists harvest-now-decrypt-later,
even though the certificate itself is still classical. That distinction is the
whole point of a per-primitive inventory.

JSON output schema:

```jsonc
{
  "target": "www.example.com",
  "scanned_at": "2026-06-04T09:54:10.721Z",
  "summary": { "findings": 5, "critical": 0, "high": 2, "medium": 2, "low": 0, "info": 1 },
  "findings": [
    {
      "id": "CSW-TLS-001",
      "severity": "high",
      "category": "tls",
      "title": "Leaf public key: RSA-2048",
      "evidence": "www.example.com:443 (www.example.com)",
      "pq_status": "vulnerable",
      "recommendation": "Plan migration to a post-quantum / hybrid certificate (ML-DSA) as CA support arrives."
    }
  ]
}
```

---

## Repository layout

```
cryptosweep/
├── src/
│   ├── cli.ts                       # Node CLI entry (cac)
│   ├── report.ts                    # Finding ontology (confidence, refs, location) + JSON/Markdown
│   ├── crypto.ts                    # Cryptographic-primitive knowledge base + standards citations
│   ├── asn1.ts                      # Minimal total DER reader (certificate signature OID)
│   ├── scanners/
│   │   ├── tls.ts                   # TLS scanner: KeyObject typing, ASN.1 sig, active hybrid probe
│   │   ├── source.ts                # Source-code crypto scanner (context-calibrated regex)
│   │   └── deps/
│   │       ├── registry.ts          # PQ-vulnerable library registry (pure data)
│   │       └── parsers/{npm,python,cargo}.ts
│   ├── output/
│   │   ├── cbom.ts                  # CycloneDX 1.6 Cryptography Bill of Materials
│   │   ├── sarif.ts                 # SARIF 2.1.0 (CI / code scanning)
│   │   └── viewer.ts                # Self-contained interactive HTML report
│   └── email/
│       ├── render.ts                # HTML + plain-text email rendering
│       └── resend.ts                # Thin fetch wrapper around the Resend API
├── tests/                           # vitest unit tests incl. real cert fixtures
└── web/                             # Cloudflare Worker landing page + scan-request capture
    ├── src/
    │   ├── landing.html             # Marketing page + email-capture form
    │   ├── api/scan-request.ts      # POST endpoint → D1 + Discord webhook
    │   ├── lib/{rate-limit,validate,discord-webhook,ip-hash}.ts
    │   └── storage/d1-schema.sql
    └── tests/                       # vitest tests with @cloudflare/vitest-pool-workers
```

The CLI and the Worker are independent. You can use one without the other.

---

## Manual fulfillment workflow (v0.1)

The hosted landing page (`web/`) captures scan requests into Cloudflare D1 and pings Discord on each new entry. Fulfillment is deliberately manual at v0.1 — you stay in the loop on every report sent out, no auto-pipeline.

1. Discord ping arrives from the Worker with the requester's email + target.
2. Generate the report:
   ```bash
   node dist/cli.js scan <target> --out /tmp/<id>.json
   ```
3. Email it:
   ```bash
   node dist/cli.js email --report /tmp/<id>.json --to <email>
   ```
4. Done — recipient receives the report via Resend within seconds.

Full deploy runbook for the Worker (Cloudflare auth, D1, KV, secrets, deploy) lives at [`docs/DEPLOY.md`](docs/DEPLOY.md).

---

## Environment variables

| Var | Where | Description |
|---|---|---|
| `RESEND_API_KEY` | CLI `email` | Required to actually send |
| `SCAN_FROM_EMAIL` | CLI `email` | Optional; defaults to `scan@cryptosweep.com`. Must be a verified Resend sender. |
| `DISCORD_WEBHOOK_URL` | Worker | Optional; Worker fires a webhook on each new scan request. Set in prod with `wrangler secret put`. |
| `IP_HASH_SECRET` | Worker | Required; HMAC key used to hash request IPs before storing |

---

## Roadmap

**v0.1 (shipped)** — CLI + TLS scanner + source scanner + deps scanner + email send + landing page + Discord webhook + manual fulfillment workflow.

**Correctness & interoperability (shipped)** — deterministic certificate typing via `KeyObject` + ASN.1 (EdDSA/DSA/RSA-PSS included), SHA-1 signatures called out distinctly, active hybrid-KEX capability probe, per-finding confidence + NIST citations, context-calibrated source scanning (no false criticals on docs/tests), and **CycloneDX 1.6 CBOM + SARIF 2.1.0 + interactive HTML outputs + a `--fail-on` CI gate**.

**v0.2 (planned)** — version-aware dependency matching against advisory data (consume the registry's `version_range`), KMS/HSM posture detection, AST-based source analysis to replace the regex first-pass.

**v0.3** — Auto-generated migration PRs (hybrid wrap + dep upgrades), continuous monitoring (scan on every PR open), Slack alerts in addition to Discord.

**v1.0** — Hosted SaaS tier: continuous PQ-readiness scanning across your GitHub org + a Cloudflare account scan, dashboard, billing.

---

## Status, scope, and trust

`cryptosweep` is pre-1.0 software, and it tells you how sure it is. The TLS scanner parses certificates with Node's `crypto`/`tls` modules and a minimal ASN.1 reader, so key type, signature algorithm, and hybrid-KEX support are `confirmed`-confidence, not guessed. The source scanner is a regex first-pass (`medium`/`low` confidence, and de-rated in docs/tests to avoid false criticals); it will miss some constructs and is not a substitute for a hand audit — an AST engine is on the roadmap. The dependency registry is hand-curated and currently version-blind (version-range matching is on the roadmap); PRs adding libraries with citations are welcome.

**This is not a cryptography implementation.** No new primitives. No new protocols. cryptosweep does not encrypt anything — it audits what other code does.

For high-stakes use (regulatory filings, board-level commitments), pair a cryptosweep report with a manual security review from a credentialed cryptographer.

---

## License

MIT — see [`LICENSE`](LICENSE).

---

## Author

Built by [Grandillionaire](https://github.com/Grandillionaire). For commercial PQ-readiness consulting engagements, reach out via the cryptosweep landing page.
