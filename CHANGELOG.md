# Changelog

All notable changes to cryptosweep are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **CycloneDX 1.6 CBOM output** (`--cbom`). Each distinct algorithm becomes a
  cryptographic-asset component carrying its CycloneDX primitive, OID, and NIST
  post-quantum security level (0 = broken by a quantum computer).
- **SARIF 2.1.0 output** (`--sarif`) with per-rule `security-severity`, so results
  drop straight into GitHub code scanning and any SARIF-aware CI.
- **Self-contained interactive HTML report** (`--html`): an offline, dependency-free
  page with summary tiles, severity and PQ-status filters, full-text search,
  drill-down to evidence and citations, and a cryptographic-asset inventory.
- **`--fail-on <severity>` CI gate**: exit code 2 when any finding meets or exceeds
  the given severity.
- **Active hybrid key-exchange probe**: cryptosweep now confirms whether a server
  will negotiate X25519MLKEM768, rather than guessing from a group name that Node
  does not expose on TLS 1.3.
- **Per-finding confidence and standards citations**: every finding reports how it
  was derived (`confirmed` down to `low`) and links to the relevant NIST / CWE /
  IETF reference.
- **SSRF guard**: scan targets that resolve to loopback, RFC 1918, link-local,
  CGNAT, or cloud-metadata addresses are refused unless `--allow-private` is set.
- **Resource ceilings** on the source walk (`maxFiles` / `maxTotalBytes`) with an
  explicit truncation finding, so a hostile or very large repository cannot exhaust
  memory and coverage limits are never silent.
- **Version-aware dependency matching**: registry entries can record a `fixedIn`
  version; installs below it are flagged, installs at or above are downgraded to
  transitional.
- **AST-based source scanner** for JavaScript and TypeScript. Weak-crypto and JWT
  matches now come from the parsed syntax tree (via @babel/parser, inlined at
  build time), so a match in a comment, a string, or a locally-shadowed name no
  longer fires, and an import-resolved call is reported at `confirmed` confidence.
  The regex sweep remains the fallback for other languages and parse failures.
- **Registry provenance**: every dependency entry carries at least one citation,
  and coverage expanded across npm, PyPI, and crates.io.
- **Opt-in OSV.dev advisory cross-reference** (`--advisories`, off by default):
  annotates flagged, pinned dependencies with known CVE advisories as a distinct
  dimension from the post-quantum verdict. Fails closed to the offline result.

### Changed

- **Certificate analysis is now deterministic.** Leaf keys are typed from a parsed
  `KeyObject` and signature algorithms from the certificate's real ASN.1 field, via
  a new minimal DER reader. Detection no longer guesses from substrings.
- The Worker rate limiter is now a **Durable Object** (atomic per key) instead of a
  non-atomic KV counter that could be bypassed under a concurrent burst.
- The source scanner is **context-calibrated**: matches in documentation or tests are
  de-rated and marked low-confidence rather than reported as false criticals.

### Fixed

- **EdDSA false negative**: an Ed25519 or Ed448 leaf certificate is now correctly
  reported as quantum-vulnerable / high, not info / unknown.
- **SHA-1 signatures** are now identified and flagged distinctly (a classical break
  today, not only a quantum one). The prior detection branch never fired.
- Elided PEM snippets in READMEs no longer trigger a false "hardcoded private key"
  critical; the rule now requires a real base64 body.
- The CLI now prints a meaningful error message instead of an empty line when a
  network handshake fails.
- The Worker's footer `/privacy` link is now a real page instead of a 404.

## [0.1.0]

- Initial release: CLI with TLS, source, and dependency scanners; JSON and Markdown
  reports; email delivery via Resend; Cloudflare Worker landing page and scan-request
  capture; manual fulfillment workflow.
