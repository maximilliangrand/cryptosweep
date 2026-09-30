# Changelog

All notable changes to cryptosweep are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-10-01

This release rolls up everything since 0.1.0, including the fixes from an
independent audit of the scanner's verdicts, its own security and its
documentation. Several headline results of earlier development builds were
wrong; they are listed under Fixed so nobody relies on them.

### Security

- **Git clones went around the SSRF guard.** Any `https://` or `git@` remote,
  including loopback and internal hosts, was cloned with the user's ambient git
  and SSH credentials, from the CLI and from MCP. Clones now go through
  `src/clone.ts`: only `https://github.com/<owner>/<repo>` by default
  (`--allow-any-git-host` on the CLI for other HTTPS and SSH remotes), the host
  vetted before a temporary directory exists and pinned for git, no shell, an
  allowlisted environment, credential helpers, hooks, symlinks, submodules and
  redirects disabled, `--depth 1`, a 120 s deadline, a 512 MiB download cap and
  a 1 GiB / 250,000-file checkout cap. The old unguarded `cloneRepo` export is
  removed.
- **DNS rebinding reached internal TLS services.** The guard resolved the name,
  then `tls.connect` resolved it again, and a DNS error let the scan through.
  A name is now resolved once, every address is vetted, every connection is
  pinned to a vetted address, and lookup errors, empty answers and non-IP
  answers fail closed.
- **Non-canonical numeric hosts** (`0177.0.0.1`, `0x7f.1`, `2130706433`) were
  judged as public addresses but resolved by glibc as loopback. They are now
  refused before any lookup. The IPv4 and IPv6 block lists gained the missing
  special-purpose ranges, and IPv6 allows only global unicast.
- **Catastrophic regex backtracking:** a 6 KB file hung the scanner. The PEM,
  cipher, requirements and pnpm-lock patterns are now linear, line numbers come
  from a per-file index, and a test sweeps every rule regex against a time
  budget.
- **MCP trust boundary.** Filesystem confinement is checked on real paths (a
  symlink inside the root no longer escapes it); an unset root no longer
  defaults to `/` or the home directory; private addresses and OSV lookups are
  switched on only by the operator (`CRYPTOSWEEP_MCP_ALLOW_PRIVATE`,
  `CRYPTOSWEEP_MCP_ADVISORIES`), and the `advisories` tool argument is gone;
  text from the scanned target is stripped of control and bidirectional
  characters before it reaches the model; tool calls are queued (2 running,
  8 waiting) and cancellable.
- File names and certificate fields with terminal escape sequences are shown
  as visible escapes in terminal and Markdown output (and replaced in MCP
  replies), and Markdown syntax in them is escaped.
- The OSV disclosure notice is printed before any dependency data is sent,
  instead of after.

### Fixed

- **The hybrid key-exchange probe reported "supports X25519MLKEM768"
  (confirmed) for TLS 1.2-only servers, including static-RSA key transport**,
  and the risk model then showed no harvest-now exposure. Each probe now offers
  one group over TLS 1.3 only and counts as accepted only when TLS 1.3
  completes with that group. A TLS 1.2 session is reported as classical key
  exchange whatever a probe says, and static RSA key transport is its own
  `high` finding.
- **Only X25519MLKEM768 was probed, and one refusal was reported as "does not
  support hybrid PQ key exchange" at confirmed confidence.** All five groups
  (X25519MLKEM768, SecP256r1MLKEM768, MLKEM768, SecP384r1MLKEM1024,
  MLKEM1024) are probed separately; the finding names the accepted or refused
  groups, and a runtime without ML-KEM is reported as a limitation of the
  scanning machine. The primary handshake offers every standard group, so
  hybrid-only and ML-KEM-only servers can be scanned. On runtimes that do not
  name TLS 1.3 groups (Node.js 22), an accepted group is attributed from the
  single-group offer, at `high` confidence.
- **CNSA 2.0 was inverted for key establishment.** Only ML-KEM-1024 groups are
  credited as the CNSA 2.0 parameter set; ML-KEM-768 hybrids are transitional.
- **Post-quantum certificate keys** (ML-DSA, SLH-DSA, ML-KEM) were typed
  `unknown`, and an ML-DSA PEM key in source was flagged as a vulnerable
  "RSA/EC" key. They are now recognised as post-quantum, in certificates and in
  source, and an unknown key algorithm no longer makes `parseCertificate` throw.
- **Intermediate signatures and RSASSA-PSS hashes were never checked**, TLS
  1.0/1.1 servers aborted the scan, TLS 1.2 was labelled transitional, and
  chain validation failures were ignored. All four are now reported.
- **The source scanner could not see Shor-vulnerable cryptography**: RSA/EC key
  generation, signing, ECDH, DH, `publicEncrypt` and WebCrypto went undetected,
  and an RSA/ECDH codebase got "No quantum-vulnerable primitives detected". It
  now has a rule table covering `node:crypto`, WebCrypto, `jsonwebtoken` and
  `jose` (parsed), and pyca/cryptography, PyCryptodome, `hashlib`, PyJWT, Go
  `crypto/*` and the Java Cryptography Architecture (regex), with weak
  parameters (RSA below 2048 bits, small curves, SHA-1/MD5 signatures) graded
  as breakable today.
- **AST resolution and scoping.** The scanner now resolves aliased and
  destructured imports, `require()`, dynamic `import()`, const aliases, member
  chains and optional chaining, through lexical scopes. The development notes
  claimed that "a locally-shadowed name no longer fires"; that was not true. It
  is now true for bindings the scanner resolves, while a shadowed call to a
  method name unique to `node:crypto` (for example `createHash`) is still
  reported, at `high` rather than `confirmed`.
- **Non-security SHA-1 (ETags, cache keys) was rated high and act-now.** The
  digest's role now sets the rating, and the risk engine only treats an
  algorithm as broken today where the scanner flagged it.
- **The JWT library downgrade applied repo-wide on one HS256 call site.** It
  now needs a direct `package.json` dependency, evidence only from the source
  under that manifest, at least one import-resolved call site, every call site
  HMAC, none runtime-chosen or unsigned, and no source coverage gap.
- **The risk engine decided harvest-now from a name list and from titles**, so
  X25519/ECDH, NaCl box and OpenPGP libraries were "on-track" even for 30-year
  data. Threats now come from structured fields (finding usage, rule id,
  registry entry, algorithm), and each source rule and TLS finding records its
  usage.
- **Present-day breaks were on the quantum clock**: a committed private key and
  JWT `alg: none` were "on-track", an MD5-signed certificate was forge-later,
  and embedded public keys were grouped as "Hardcoded private key". These are
  now `act-now`, and public and private keys are separate assets.
- **Migration-time defaults** were unrealistically short and could not be
  overridden. They are now 3 years for key establishment and 5 for signatures,
  documented against the UK NCSC timeline, with `--migration-years` (CLI) and
  `migrationYears` (MCP); invalid numbers are rejected instead of producing
  "on-track".
- **SARIF rule identity collapsed**: MD5, SHA-1, DES and RC4 shared one rule,
  as did RS256 and HS256, and private and public keys, with the description
  and severity of whichever result sorted first. Every detector now has its
  own rule id and a description from the rule catalogue, and every result
  carries its own severity. File paths use one base (`%SRCROOT%`) for source and
  dependency findings, and tool URLs point to the current repository.
- **CBOM**: signature algorithms carried key OIDs, NIST levels were wrong, RC4
  was a block cipher, dependency findings were dropped and assets were made up
  from titles. Signature OIDs come from the certificate, levels follow FIPS
  203/204/205, dependencies are library components with a purl and version,
  certificates carry subject, issuer and validity, and every asset records
  where it was seen.
- **Registry corrections**: rustls gained X25519MLKEM768 in 0.23.22, not 0.23.0;
  `oqs-python` is published as `liboqs-python`; `cryptography` ships ML-KEM
  and ML-DSA in its standard wheels from 48.0.0; the JOSE libraries point to ML-DSA (RFC 9964) and OpenPGP to RFC
  9980; crypto-js is `unknown` (it has no asymmetric primitives).
- **Dependency parsing** dropped dependencies from TOML tables and ignored
  lockfiles. A table-aware TOML reader backs `pyproject.toml` and `Cargo.toml`,
  and `package-lock.json`, `yarn.lock`, `Cargo.lock`, `poetry.lock`, `uv.lock`
  and `Pipfile(.lock)` are parsed. Python names follow PEP 503.
- **Silent coverage gaps.** Oversized, binary, capped and unparsed files,
  unsupported manifests and resource limits are reported as coverage findings,
  and the report records what each check covered. An empty result reads "No
  findings from the checks that ran" with its scope, not "No quantum-vulnerable
  primitives detected".
- **`cryptosweep-mcp` exited silently when started through a symlink**,
  including the npm and pnpm bin shims. The bin now always starts the server.
  Stdin EOF no longer drops in-flight results, cancellation is honoured, and
  malformed input gets JSON-RPC error replies.
- **CLI validation** ran some checks after the scan and output files were
  written, and `--out 1` wrote to stdout. Every option is now validated first.
- **Target classification** misrouted common input (a mistyped `./path` went to
  github.com, `a.b/c` was a repository, IPv6 literals could not be scanned).
- Citations: the hybrid groups cite RFC 10024 (formerly
  draft-ietf-tls-ecdhe-mlkem) and RFC 9954; NIST IR 8547 dates, DSA's FIPS
  186-5 withdrawal and the ABA Model Rule 1.6(c) label (a safeguarding duty,
  not technological competence) are corrected.

### Added

- CycloneDX 1.6 CBOM (`--cbom`), SARIF 2.1.0 (`--sarif`), a self-contained
  HTML report (`--html`) and the risk model as JSON (`--risk`). The test suite
  validates generated CBOM and SARIF documents against the official schemas.
- `--fail-on <severity>` CI gate (exit code 2).
- Certificate analysis from a parsed `KeyObject` and the certificate's ASN.1
  `signatureAlgorithm` field, with SHA-1 and MD5 signatures called out.
- Crypto-agility risk engine (Mosca clock, harvest ledger, data classes) with
  `--data-class`, `--crqc-year` and `--migration-years`.
- MCP server (`cryptosweep-mcp`) with `scan` and `data_classes` tools, and an
  Urfael plugin manifest.
- Version-aware dependency matching where the registry records a `fixedIn`.
- Opt-in OSV.dev advisory cross-reference (`--advisories`).
- Per-finding confidence and rule ids; standards citations on the findings
  whose classification rests on one.
- Resource ceilings on the source and dependency walks.
- CI on Node.js 22 and 26 (`.github/workflows/ci.yml`), including a check that
  the build reproduces the committed viewer bundle.

### Changed

- Node.js 22 or later is required (was 20). The post-quantum probe needs a
  Node.js build with OpenSSL 3.5 or later.
- Key and signature severity grades classical strength, separately from the
  post-quantum verdict: RSA-2048, P-256 and Ed25519 are `medium`, anything
  below the SP 800-131A floor or signed with SHA-1/MD5 is `high`/`critical`.
- Matches in documentation and tests are de-rated and marked low-confidence.
- The bins are built as ESM only, and sourcemaps are left out of the published
  files (about 7 MB unpacked instead of 23.5 MB).

### Removed

- The Cloudflare Worker landing page (`web/`), which captured scan requests
  into D1 and forwarded requester emails to a Discord webhook, and its
  workspace entry and environment variables (`DISCORD_WEBHOOK_URL`,
  `IP_HASH_SECRET`).
- The `email` command and its Resend client (`RESEND_API_KEY`,
  `SCAN_FROM_EMAIL`).

## [0.1.0]

- Initial release: CLI with TLS, source, and dependency scanners; JSON and Markdown
  reports; email delivery via Resend; Cloudflare Worker landing page and scan-request
  capture; manual fulfillment workflow.
