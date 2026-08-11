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
  Every IPv6 spelling of an address is normalized to its 16 bytes before
  classification, including IPv4-mapped, IPv4-compatible, NAT64, and 6to4 forms.
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

- **Key and signature severity now grades classical strength, separately from the
  post-quantum verdict.** A classically sound but pre-quantum key or signature
  (RSA-2048+, P-256+, Ed25519, SHA-256 RSA) is `medium`; anything below the SP
  800-131A floor, or signed with SHA-1/MD5, is `high`/`critical`. `pq_status` is
  unchanged. Previously every recognized key type was `high`, which made
  `--fail-on high` red for every host on the public internet and left RSA-1024
  and RSA-4096 indistinguishable.
- **Dependency findings are reconciled against confirmed source evidence.** When
  the AST scanner has structurally confirmed that every JWT algorithm in a
  codebase is HMAC, the JWT library's registry finding is downgraded instead of
  asserting a quantum-vulnerable verdict the tool itself disproved at higher
  confidence.
- **Per-obligation attribution is derived, not constant.** Obligations declare
  which failure modes (confidentiality / identity / classical strength) breach
  them, and the harvest ledger counts only the assets that actually match.
- **The MCP server no longer exposes `allowPrivate`,** and filesystem targets are
  confined to `CRYPTOSWEEP_MCP_ROOT` (the working directory by default), so a
  prompt-injected client cannot probe the internal network or walk the disk.
  Messages are also dispatched independently, so a long scan no longer blocks
  `ping` and notifications behind it.
- **Certificate analysis is now deterministic.** Leaf keys are typed from a parsed
  `KeyObject` and signature algorithms from the certificate's real ASN.1 field, via
  a new minimal DER reader. Detection no longer guesses from substrings.
- The Worker rate limiter is now a **Durable Object** (atomic per key) instead of a
  non-atomic KV counter that could be bypassed under a concurrent burst.
- The source scanner is **context-calibrated**: matches in documentation or tests are
  de-rated and marked low-confidence rather than reported as false criticals.

### Fixed

- **SSRF bypass via non-dotted IPv4-mapped IPv6.** The guard matched only the
  textual `::ffff:1.2.3.4` form, so `::ffff:7f00:1` (loopback) and
  `::ffff:a9fe:a9fe` (the cloud-metadata endpoint) were allowed through, as were
  `0:0:0:0:0:0:0:1` and `::0.0.0.0`. Addresses are now canonicalized to bytes
  before classification, and an unparseable literal fails closed.
- **MD5/MD2-signed certificates were the quietest finding in the report.** Their
  OIDs were missing from the signature table, and an unrecognized OID was rated
  `info`/`unknown`. MD2/MD4/MD5 are now `critical`, an unrecognized signature
  algorithm is `medium` "needs review", and the table gained the SHA-224 variants
  and all twelve SLH-DSA parameter sets.
- **One unreadable or oversized file aborted the entire source scan** and
  discarded every finding already collected. Size is now checked with `stat`
  before the read (so a file above the cap is never buffered), and per-file I/O
  failures degrade to an explicit coverage finding.
- **Passphrase-encrypted PEM private keys were never detected.** The rule now
  skips the RFC 1421 `Proc-Type:` / `DEK-Info:` header block before requiring a
  base64 body.
- **The certificate-chain finding fabricated its evidence**: it printed each
  certificate's issuer instead of its subject, counted the locally-supplied trust
  anchor as an intermediate, and asserted "using classical crypto" without ever
  reading a key type. It now names the real intermediates' subjects and key types
  and derives the verdict from them.
- **The CBOM silently dropped every finding without an `algorithm`**, so hardcoded
  private keys, the certificate chain, and the protocol finding never appeared in
  the "Bill of Materials". They are now emitted with the appropriate CycloneDX
  `assetType`.
- **SARIF results for TLS findings carried no `locations`**, so GitHub code
  scanning had nothing to anchor an alert to. Network findings now populate
  `Location.host` / `Location.port` and emit a `tls://host:port` artifact plus a
  logical location.
- **EdDSA false negative**: an Ed25519 or Ed448 leaf certificate is now correctly
  reported as quantum-vulnerable, not info / unknown.
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
