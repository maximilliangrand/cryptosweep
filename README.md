# cryptosweep

An open-source developer tool for inventorying the cryptography a system uses and planning its post-quantum migration.

cryptosweep scans TLS endpoints, source code and dependency manifests, records each cryptographic primitive it finds, and flags the ones a cryptographically relevant quantum computer would break (RSA, ECDSA, EdDSA, DSA, classical Diffie-Hellman) alongside the ones that are already broken today (MD5, SHA-1 signatures, DES, RC4, undersized keys, committed private keys). It writes JSON, Markdown, a CycloneDX 1.6 CBOM, SARIF 2.1.0 and a self-contained HTML report, and it can run as a CI gate or as an MCP server.

It is a scanner, not a cryptography library: it implements no primitives and changes nothing it scans. Every finding says how it was derived (`confidence`), and the report records what each check covered, so a short result is never presented as proof that nothing else is there.

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Targets](#targets)
- [What each scanner covers](#what-each-scanner-covers)
- [The post-quantum key-exchange probe](#the-post-quantum-key-exchange-probe)
- [Risk engine](#risk-engine)
- [Outputs](#outputs)
- [CI gate and exit codes](#ci-gate-and-exit-codes)
- [MCP server](#mcp-server)
- [Network behaviour](#network-behaviour)
- [CLI reference](#cli-reference)
- [Library use](#library-use)
- [Limitations](#limitations)
- [Development](#development)

## Install

cryptosweep is not published to a package registry. Build it from source; it needs Node.js 22.20 or later and pnpm.

```bash
git clone https://github.com/maximilliangrand/cryptosweep.git
cd cryptosweep
pnpm install --frozen-lockfile
pnpm build
node dist/cli.js --help
```

The build produces two executables, `dist/cli.js` (`cryptosweep`) and `dist/mcp.js` (`cryptosweep-mcp`), plus the library in `dist/index.js` and `dist/index.cjs`. The only runtime dependency is `cac`; the JavaScript parser and the HTML viewer are bundled at build time.

The TLS scanner's post-quantum probe also needs the Node.js build to use OpenSSL 3.5 or later, the first release with ML-KEM TLS groups. Check with `node -p process.versions.openssl`; Node.js 22.0 to 22.19 ship OpenSSL 3.0, which is why the floor is 22.20, and the official Node.js 22.23.3 and 26.10.0 builds ship OpenSSL 3.5.8. On an older OpenSSL (a custom or system-OpenSSL build) the rest of the TLS scan still runs, and the report says the key exchange could not be tested. A server that accepts only ML-KEM groups refuses every handshake such a runtime can offer; the report then records the refusal (`tls/handshake-refused`) and marks the certificate, protocol and key exchange as not assessed instead of failing the scan.

## Quick start

```bash
# A local directory: source code and dependency manifests
node dist/cli.js scan ./my-service

# A public GitHub repository (shallow clone, then the same scans)
node dist/cli.js scan owner/repo

# A TLS endpoint
node dist/cli.js scan example.com

# Every output format at once, with the risk model for 10-year data
node dist/cli.js scan ./my-service --data-class financial-pii \
  --out report.json --md report.md --cbom cbom.json \
  --sarif results.sarif --html report.html --risk risk.json

# CI: fail (exit 2) when anything is high or worse
node dist/cli.js scan . --sarif results.sarif --fail-on high
```

Without an output flag the Markdown report goes to stdout. The risk summary always goes to stderr, so stdout stays clean for piping.

An abridged run on a small sample project (a `package.json` with `jsonwebtoken` and `node-forge`, and one TypeScript file that signs an RS256 token, runs ECDH on P-256 and computes an ETag with SHA-1); long titles are cut at `...`:

```text
| Severity  | Category | PQ status  | Confidence | Finding                                                  | Evidence                        |
| 🟧 high   | jwt      | vulnerable | confirmed  | JWT RSA signature algorithm via jsonwebtoken (RS256)     | src/auth.ts:5                   |
| 🟧 high   | deps     | vulnerable | medium     | jsonwebtoken (npm): Widely used JWT (JWS) library; ...   | package.json:jsonwebtoken@9.0.2 |
| 🟨 medium | source   | vulnerable | confirmed  | ECDH key agreement via node:crypto (P-256)               | src/auth.ts:9                   |
| 🟨 medium | deps     | vulnerable | medium     | node-forge (npm): Legacy crypto toolkit ...              | package.json:node-forge@1.3.1   |
| 🟦 low    | source   | unknown    | high       | Weak hash in a non-security role via node:crypto (sha1)  | src/auth.ts:15                  |

crypto-agility risk (data class Financial / PII, 10yr horizon, CRQC assumed 2035):
  exposed(HNDL) 2  overdue 0  act-now(classical) 0  on-track 2  |  16 risk-years exposed
```

The ECDH call and `node-forge` (key establishment and encryption) are harvest-now-decrypt-later exposures for data that must stay secret for 10 years; the RS256 signature and `jsonwebtoken` are on the forge-later clock; the SHA-1 ETag protects nothing that depends on collision resistance, so it stays off the board. The Markdown report also lists every recommendation and a coverage section.

## Targets

`scan <target>` decides what the target is in a fixed order, so an ambiguous string is never guessed at:

1. An explicit path (`./x`, `../x`, `/x`, `~`, `~/x`, `C:\x`) is always local. A missing directory is an error, never a GitHub lookup.
2. An existing directory is scanned in place.
3. A URL or git remote: `https://github.com/owner/repo` is cloned; any other `https://` URL is a TLS target (`https://host:8443/path` scans `host:8443`). `git@host:path`, `ssh://` and other `.git` remotes are clone targets, refused unless `--allow-any-git-host` is given.
4. An IPv6 literal, bare or bracketed (`[2001:db8::1]:443`), is a TLS target.
5. `owner/repo` (valid GitHub owner and repository names) is cloned from GitHub.
6. Anything else is `host[:port]` for a TLS scan. `a.b/c` is the host `a.b`, not a repository.

A directory or repository gets the source and dependency scans; a host gets the TLS scan. A repository has no endpoint of its own, so scan its deployed hostname separately for TLS posture.

## What each scanner covers

### Source scanner

Every detector is a row in a rule table (`src/scanners/source-rules.ts`) with a stable rule id, the primitive it inventories, how that primitive is used, and the highest confidence a match can earn. Findings carry that rule id, which SARIF, the CBOM and the risk engine use.

**JavaScript and TypeScript** (`.js .jsx .mjs .cjs .ts .tsx .mts .cts`) are parsed to an AST with `@babel/parser`, so a match in a comment or an unrelated string does not fire. Callees are resolved through imports and `require()` (aliased, destructured, dynamic `import()`, const aliases, member chains, optional chaining, TypeScript wrappers, transpiled output), with lexical scoping. A call resolved to its module earns `confirmed`, except where part of the verdict is inferred: an MD5 or SHA-1 hash (its role comes from names, see below) and `jsonwebtoken`'s implicit HS256 default top out at `high`. An unresolved call whose method name is unique to `node:crypto` (for example `createHash`) is still reported, at `high`. The APIs covered:

| API | Calls |
| --- | --- |
| `node:crypto` | `generateKeyPair(Sync)` (RSA, DSA, EC, Ed25519/Ed448, X25519/X448, DH), `createSign`/`createVerify`, `sign`/`verify`, `createECDH`, `createDiffieHellman(Group)`, `getDiffieHellman`, `diffieHellman`, `publicEncrypt`/`privateDecrypt`, `privateEncrypt`/`publicDecrypt`, `createHash`/`hash` (MD5, SHA-1), `createCipheriv`/`createDecipheriv` and the legacy `createCipher` (DES, 3DES, RC2, RC4), `createHmac`/`hkdf`/`pbkdf2` over MD5 or SHA-1 |
| WebCrypto (`crypto.subtle`) | `generateKey`, `importKey`, `unwrapKey`, `sign`/`verify`, `deriveKey`/`deriveBits`, `encrypt`/`decrypt`, `wrapKey` for RSA, ECDSA, ECDH, Ed25519/Ed448, X25519/X448 and RSA-OAEP; a call whose algorithm is computed at runtime (as in `jose`) is an `info` marker to trace |
| `jsonwebtoken` | `sign`/`verify`, including its implicit HS256 default and algorithms chosen at runtime |
| `jose` | JWS and JWE builders (`setProtectedHeader`), `*Verify`, `*Decrypt`, key import and generation, `UnsecuredJWT` |

A JavaScript file that does not parse (or is over 1 MB) falls back to the lower-confidence regex sweep, and the report says so. The sweep reports a quoted `"none"` as an unsigned JWT only when it is assigned to an `alg`, `algorithm` or `algorithms` key, in a file that names `jsonwebtoken` or calls `jwt.sign`, `jwt.verify` or `jwt.decode`.

**Python, Go and JVM languages** are matched with linear-time regular expressions over the file with its comments blanked out, at `medium` confidence at most:

| Language | Libraries |
| --- | --- |
| Python (`.py .pyw .pyi`) | pyca/cryptography (RSA, EC, DSA, Ed25519/Ed448, DH, X25519/X448, ECDH, ECDSA, RSA padding, RSA-OAEP), PyCryptodome (RSA, ECC, DSA, OAEP, PKCS#1 signatures, DSS, weak hashes and ciphers), `hashlib` (MD5, SHA-1; `usedforsecurity=False` is honoured), PyJWT and python-jose |
| Go (`.go`) | `crypto/rsa`, `crypto/ecdsa`, `crypto/ecdh`, `crypto/elliptic`, `crypto/dsa`, `crypto/ed25519`, `golang.org/x/crypto/curve25519`, `crypto/md5`, `crypto/sha1`, `crypto/des`, `crypto/rc4` |
| Java, Kotlin, Scala, Groovy | JCA `KeyPairGenerator`, `Signature`, `KeyAgreement`, `Cipher` and `MessageDigest` with classical or weak algorithm names |

Other text files get the JavaScript regex sweep. Dependency manifests and lockfiles are left to the dependency scanner.

**PEM key blocks** are looked for in every file, in every language. A private key block (`RSA`, `EC`, `DSA`, `OPENSSH`, `ENCRYPTED`, PKCS#8 or PGP) is `critical`; when it parses (unencrypted PKCS#1, SEC 1 or PKCS#8) its algorithm is recorded, and a post-quantum one is `pq_status` safe, since the leak, not the algorithm, is the problem. A public key is parsed: a classical key is graded by type and size (RSA-1024 is `high`, below the SP 800-131A floor), an ML-DSA, SLH-DSA or ML-KEM key is reported as post-quantum, and a block that does not parse is reported at lower confidence (as RSA if its label says so, otherwise as an unknown algorithm).

Severity grades classical strength and `pq_status` carries the quantum verdict. A sound RSA-2048 key generation is `medium` and quantum-vulnerable; a modulus or Diffie-Hellman group under 2048 bits, a curve under 224 bits, or a signature over MD5 or SHA-1 is raised to `high` or `critical`, and the finding records why (`classicalBreak`), which puts it on the risk engine's act-now board.

For MD5 and SHA-1 digests the names around the call set the rating, a heuristic rather than proof. In JavaScript and TypeScript the AST reads the variable or property the digest is assigned to, the calls it feeds (including the parts of a concatenated argument), the enclosing function, and where its variable is used in the statements that follow (`res.setHeader("ETag", digest)`, `if (secWSAccept !== digest)`). In Python, Go, the JVM and the JavaScript regex fallback only the identifiers and strings on the match's own line are read (`etag = hashlib.md5(body)`), and `hashlib`'s `usedforsecurity=False` is honoured. A password, token or signature context is `high`; an ETag, cache key, git object id or the WebSocket handshake (RFC 6455 `Sec-WebSocket-Accept`) is `low` with `pq_status` unknown and stays off the risk board; anything else is `medium` and, as a weak hash with no stated role, act-now.

Matches under documentation, test, fixture and example paths (key blocks included) are de-rated two severity steps, marked `low` confidence, carry `location.context`, and are kept out of the risk ledger.

The walk skips dependency, build, virtual-environment and cache directories below the scan root: `node_modules`, `.git`, `dist`, `build`, `coverage`, `.next`, `out`, `vendor`, `.turbo`, `target`, `.venv`, `venv`, `.tox`, `.nox`, `__pycache__`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, and any directory holding a `pyvenv.cfg` (a Python virtual environment under any name) or a `CACHEDIR.TAG`. The dependency scanner walks with the same list. The skip is recorded as an `info` finding and in the coverage scope; to include such a directory, scan it directly (the same defaults then apply below it). The walk visits directories in sorted order and does not follow symlinks. It stops at 25,000 files or 300 MB read, skips files over 2 MB, binary files (only their first 8 KB is read) and source maps, and reports at most 500 findings per file. Each of those gaps, and every unreadable path, becomes an `info` coverage finding; source maps and binaries whose extension says they hold no code (images, fonts, media, PDF, WebAssembly, Python bytecode) are listed without marking coverage partial, while key stores (`.der`, `.p12`, `.pfx`, `.jks`) and unknown binaries do.

### Dependency scanner

The dependency scanner reads these files and matches the packages against a built-in registry of 31 cryptography libraries (10 npm, 10 PyPI, 11 crates.io), each with a cited reason, a post-quantum status, what the library is used for and which algorithms it provides:

| Ecosystem | Files |
| --- | --- |
| npm | `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` (v1 and Berry) |
| PyPI | requirements files (`requirements*.txt`, `*requirements*.in`, `constraints*.txt`, anything under `requirements/`), `pyproject.toml` (PEP 621 dependencies and optional dependencies, dependency groups, Poetry, PDM and uv tables), `poetry.lock`, `uv.lock`, `Pipfile`, `Pipfile.lock` |
| crates.io | `Cargo.toml` (including target-specific, workspace and renamed dependencies), `Cargo.lock` |

Python names are normalised per PEP 503, and pip line continuations and per-requirement options (`--hash=...`) are handled. Matching is version-aware only where the registry records the release that added post-quantum support (`fixedIn`: `cryptography` 48.0.0 and `rustls` 0.23.22). Below it both are quantum-vulnerable; a declaration is judged as the range it is (npm, Cargo and PEP 440 operators, wildcards, conjunctions and `||`, with Cargo's bare-version caret made explicit): an exact pin or a range capped below `fixedIn` is reported at `high` confidence, a range entirely at or above it is transitional, and a range that admits both (`>=41`, a Cargo `0.23`, `*`) is flagged at `low` confidence with a note to resolve it from the lockfile, as is an unreadable version. A manifest under a test, fixture, example or documentation directory is de-rated like a source match there. Other dependency files (`go.mod`, `pom.xml`, Gradle, `Gemfile.lock`, `composer.lock`, `setup.py`, `bun.lock`, .NET, Swift, Dart, Elixir and C/C++ package files) are not parsed; they are listed in a coverage finding rather than silently ignored.

One finding can be lowered by source evidence: a `jsonwebtoken` dependency declared directly in a `package.json`, when the source under that manifest has at least one import-resolved call site, every call site pins an HMAC algorithm, none is unsigned or chooses its algorithm at runtime, and the source scan had no coverage gap. The lowered finding cites the call sites. No other library is reconciled, and nothing is ever raised or cleared this way.

`--advisories` adds known CVE advisories from [OSV.dev](https://osv.dev) to flagged dependencies pinned to one release (a range such as `>=41` or a Cargo caret is not looked up). It is off by default, it sends the package names, versions and ecosystems to `api.osv.dev`, the notice is printed before anything is sent, and a lookup failure leaves the offline result unchanged. Advisories never change a finding's severity or post-quantum status.

### TLS scanner

For a host, the TLS scanner reports:

- the leaf public key, typed from a parsed `KeyObject` (RSA, RSA-PSS, DSA, EC with its curve, Ed25519/Ed448, ML-DSA, SLH-DSA, ML-KEM), with the key's algorithm OID as a fallback when the local OpenSSL cannot decode a post-quantum key (which also covers HSS/LMS, XMSS and XMSS^MT);
- the leaf signature algorithm, read from the certificate's ASN.1 `signatureAlgorithm` field (RSASSA-PSS with its hash; SHA-1 is `high`, MD2/MD4/MD5 is `critical`; ML-DSA, SLH-DSA, their pre-hash HashML-DSA and HashSLH-DSA variants, HSS/LMS and XMSS are post-quantum; an unrecognised OID is `medium` for review);
- every intermediate the server sent, judged on both its key and its signature, with SHA-1, MD5 or unrecognised intermediate signatures called out separately;
- whether the chain validated against the local trust store and the host name, and whether the leaf has expired or expires within 30 days;
- the negotiated protocol version (TLS 1.2 is quantum-vulnerable because ML-KEM groups exist only for TLS 1.3; TLS 1.0 and 1.1 are `high`; TLS 1.3 itself is not graded, the key exchange is), and the key exchange: static RSA key transport (no forward secrecy), DHE below 2048 bits (classically broken), ECDHE with its curve, or a post-quantum group.

A server that refuses the modern client offer at the TLS layer gets one retry with a legacy offer (TLS 1.0 and up, OpenSSL security level 0), so an obsolete server is reported instead of aborting the scan. Certificates are read with verification off, so an untrusted chain is still inventoried and its validation failure is its own finding.

## The post-quantum key-exchange probe

The primary handshake offers the groups a current browser leads with (X25519MLKEM768, then X25519) followed by every other standard group, so a server that only accepts a NIST-curve hybrid or pure ML-KEM still completes a handshake. Then each post-quantum group is offered on its own, over TLS 1.3 only:

| Group | Kind | ML-KEM parameter set | Specification |
| --- | --- | --- | --- |
| X25519MLKEM768 | hybrid | ML-KEM-768 | RFC 10024 |
| SecP256r1MLKEM768 | hybrid | ML-KEM-768 | RFC 10024 |
| MLKEM768 | pure | ML-KEM-768 | draft-ietf-tls-mlkem |
| SecP384r1MLKEM1024 | hybrid | ML-KEM-1024 | RFC 10024 |
| MLKEM1024 | pure | ML-KEM-1024 | draft-ietf-tls-mlkem |

A group counts as accepted only when the handshake completes as TLS 1.3 and either the runtime names that group as negotiated, or (on runtimes such as Node.js 22 that do not report TLS 1.3 groups) the offer contained only that group, which RFC 8446 requires the server to use. The second case is rated `high` rather than `confirmed`. A TLS 1.2 server can never pass: the probe will not complete below TLS 1.3, and a TLS 1.2 session is reported as classical key exchange whatever any probe says.

The finding lists the groups the server accepted. If it accepted none, it lists the groups it refused (`high` confidence when all five were refused, `medium` otherwise). Groups the local OpenSSL lacks are marked untestable, and if none can be tested the result is an `info` limitation of the scanning machine, not a verdict on the server. Only ML-KEM-1024 groups are credited as the CNSA 2.0 key-establishment parameter set; ML-KEM-768 hybrids are labelled transitional and not CNSA 2.0 compliant, and pure ML-KEM is post-quantum safe.

Support means that sessions with clients that offer these groups resist harvest-now-decrypt-later. It does not mean every session does: clients that do not offer them still get classical key exchange, and the certificate is judged separately.

What one scan does not assess (the protocol finding states the first item): other protocol versions and cipher suites the server also accepts (only the ones negotiated for this client offer are observed), which group the server prefers when a client offers several, the symmetric strength CNSA 2.0 also requires (AES-256, SHA-384), certificates the server sent that Node's issuer walk drops, revocation, and anything above the TLS layer.

## Risk engine

The risk engine turns findings into a per-asset verdict with Mosca's inequality: if X (how long the data must stay secret) plus Y (how long the migration takes) is greater than Z (years until a cryptographically relevant quantum computer), data protected today is already exposed.

Each asset (one per rule and algorithm) gets a threat model, decided from structured fields (the finding's usage, its rule id, the registry entry, then the algorithm label), never from titles:

- **harvest-now**: key establishment and encryption. Recorded traffic or ciphertext can be decrypted later, so X applies. Status is `exposed` (X > Z), `overdue` (X + Y > Z) or `on-track`. Only these assets count toward the harvest ledger.
- **forge-later**: signatures and authentication. There is nothing to harvest; the migration must finish before Z. Status is `overdue` (Y > Z), `on-track`, or `exposed` once the assumed CRQC year has passed.
- **classical**: broken today, whatever the quantum timeline. A committed private key, JWT `alg: none`, MD2/MD4/MD5 and SHA-1 (in certificate signature names such as `md5WithRSAEncryption`, and in source-code signatures such as `createSign("RSA-SHA1")`, JCA `SHA1withRSA`, WebCrypto RSASSA with SHA-1 or Go `SignPKCS1v15` with `crypto.SHA1`), DES, 3DES, RC2, RC4, keys and groups below the SP 800-131A minimum (RSA, DSA and finite-field Diffie-Hellman below 2048 bits, including DHE-1024 key exchange; ECC below a 224-bit curve, including P-192), and TLS below 1.2. The scanners record the parameters that make a finding broken (`classicalBreak`), so this does not depend on the algorithm label. Status is `act-now`.

An asset whose use the evidence does not determine (a bare RSA key can sign or decrypt) is assessed under both models and gets the more urgent verdict; its rationale says so. A digest a scanner found in a non-security role is not flagged. One TLS endpoint's key establishment is one asset: the key exchange, a TLS 1.2 protocol and, under static RSA, the leaf key that decrypts the premaster secret are a single harvest-now exposure.

Findings under documentation, test, fixture and example paths are assessed the same way but listed separately (`nonProductionAssets`): no ledger count, risk-year or obligation includes them, and the headline says how many there are. The algorithm vocabulary the risk engine reads labels with is the CBOM's (`src/algorithms.ts`).

Assumptions, all overridable, and printed with every risk model:

- **Z**: the CRQC year defaults to 2035 (`--crqc-year`). This is an assumption, not a forecast: it is the planning date shared by US NSM-10, NIST IR 8547 (draft) and the UK NCSC migration timeline.
- **Y**: migration takes 3 years for key establishment and 5 for signatures and PKI by default, following the UK NCSC 2025 timeline and the length of the SHA-1 certificate sunset. `--migration-years` applies one value to every asset.
- **X**: set by the data class (`--data-class`); horizons are typical values, not legal advice.

| Data class | Horizon (X) | Obligations counted |
| --- | --- | --- |
| `legal-privileged` | 30 years | ABA Model Rule 1.6(c) safeguarding duty, harvest-now exposure |
| `medical-phi` | 25 years | HIPAA Security Rule, harvest-now exposure |
| `government-cui` | 25 years | NSA CNSA 2.0 (binding on National Security Systems), harvest-now exposure |
| `financial-pii` | 10 years | harvest-now exposure |
| `secrets` | 5 years | harvest-now exposure |
| `general` (default) | 7 years | harvest-now exposure |
| `public` | 0 years | none |

Obligations are attributed by failure mode: the harvest-now obligation counts exposed and overdue confidentiality assets, the ABA and HIPAA duties also count already-broken crypto, and CNSA 2.0 counts every public-key asset outside the parameter sets it specifies (ML-KEM-1024, alone or in the SecP384r1 hybrid, and ML-DSA-87; LMS and XMSS for software and firmware signing), whatever its Mosca status, since CNSA 2.0 sets its own deadlines. Its AES-256 and SHA-384 requirements are not assessed.

The ledger's headline number is the sum, over exposed harvest-now assets, of horizon years times the data class's sensitivity weight: a transparent ranking aid, not a monetary figure. `--risk <file>` writes the whole model (assets, verdicts with rationale, ledger, and a graph linking assets to the data class and obligations).

## Outputs

| Flag | Format | Contents |
| --- | --- | --- |
| (none) | Markdown on stdout | Findings table, recommendations, coverage |
| `--out` | JSON | The full report: findings with rule id, severity, confidence, `pq_status`, algorithm, usage, references and location (with `context` for documentation and test paths), the reason a primitive is classically broken (`classicalBreak`) and its CNSA 2.0 standing (`cnsa2`) where a scanner determined them, plus coverage |
| `--md` | Markdown | As stdout. Every field from the scanned target is escaped |
| `--cbom` | CycloneDX 1.6 CBOM | Algorithm assets with CycloneDX primitive, OID (the one read from the certificate when there is one) and NIST quantum security level where the label determines it (a test runs every label the scanners can emit through the shared vocabulary; only an unparseable key or unrecognised OID stays `unknown`); certificates with subject, issuer and validity linked to their signature algorithm and public key; key material (committed private keys marked compromised); the negotiated protocol; flagged dependencies as library components with a purl, linked to the algorithms they provide |
| `--sarif` | SARIF 2.1.0 | One rule per rule id with a stable description; every result carries its own level and `security-severity`; file locations are relative to `%SRCROOT%`, TLS findings are anchored at `tls://host:port` |
| `--html` | HTML | A single offline file (React 18 and Blueprint 5 inlined from the lockfile, no network requests): risk summary, coverage, severity and status filters, search, evidence and citations |
| `--risk` | JSON | The risk model described above |

The test suite validates CBOM and SARIF documents generated from scanner output against the official JSON schemas (CycloneDX 1.6 and OASIS SARIF 2.1.0 errata 01), vendored unmodified under `tests/fixtures/schemas/`. Text that comes from the scanned target (file names, certificate subjects, manifest versions) has terminal-control and bidirectional-override characters made visible as escapes in the report, and replaced in MCP replies.

## CI gate and exit codes

| Exit code | Meaning |
| --- | --- |
| 0 | The scan completed (findings may exist) |
| 1 | Invalid input or a failed scan (every option is validated before any network request or file write) |
| 2 | `--fail-on <severity>` was given and at least one finding is at or above it |
| 130 / 143 | Interrupted by SIGINT / SIGTERM: the scan was aborted and any partial clone removed (a second signal exits at once) |

`--fail-on info` fails on any finding at all, including coverage notes. A GitHub Actions job that gates on `high` and uploads the SARIF to code scanning:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v7
  - uses: pnpm/action-setup@v6
    with:
      version: 12.6.0
  - uses: actions/setup-node@v7
    with:
      node-version: 26
  # Built outside the workspace, so the scan does not include cryptosweep's own test fixtures.
  - name: Build cryptosweep
    run: |
      git clone --depth 1 https://github.com/maximilliangrand/cryptosweep "$RUNNER_TEMP/cryptosweep"
      cd "$RUNNER_TEMP/cryptosweep" && pnpm install --frozen-lockfile && pnpm build
  - run: node "$RUNNER_TEMP/cryptosweep/dist/cli.js" scan . --sarif results.sarif --fail-on high
  - if: always() && hashFiles('results.sarif') != ''
    uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: results.sarif
```

The SARIF file is written before the gate is evaluated, so it is uploaded even when the job fails on findings.

## MCP server

`cryptosweep-mcp` (`dist/mcp.js`) is a Model Context Protocol server over stdio (JSON-RPC 2.0, protocol version 2024-11-05) with two tools:

- `scan(target, dataClass?, crqcYear?, migrationYears?)`: the same scans and risk model as the CLI, returned as text (the first 12 findings, the risk summary and the coverage).
- `data_classes()`: the data classes and their horizons.

An MCP server acts on text a model has read, so tool arguments are never trusted with anything that widens what a scan can reach. That is decided only by the operator, through the server's launch environment:

| Variable | Effect |
| --- | --- |
| `CRYPTOSWEEP_MCP_ROOT` | Directory filesystem targets must stay inside, compared after resolving symlinks, so a link inside the root cannot escape it. Relative targets resolve against it. If unset, the working directory is used, unless it is `/`, the home directory or an ancestor of it, in which case filesystem scans are refused |
| `CRYPTOSWEEP_MCP_ALLOW_PRIVATE=1` | Let the SSRF guard pass non-public addresses (off by default) |
| `CRYPTOSWEEP_MCP_ADVISORIES=1` | Send flagged, pinned dependencies to OSV.dev (off by default) |

Filesystem targets are confined before anything touches the disk or the network: a target shaped like a path (a path prefix, a backslash, a `..` segment, or a `/` that is not GitHub `owner/repo`) is checked lexically against the root first, so every path outside it gets the same refusal whether or not it exists, and `~` is not expanded. Unlike the CLI, the MCP server therefore reads `example.com/login` as a path, not as the host `example.com`. Clones from the MCP server are limited to public GitHub repositories; `--allow-any-git-host` has no MCP equivalent. Control, line-separator and bidirectional characters are replaced in everything sent to the model, including errors. At most 2 tool calls run at once and 8 wait; beyond that the server answers "busy". `notifications/cancelled` drops a queued call or aborts a running one: its clone, directory walks and TLS connections stop, and its response is suppressed. When stdin closes, every accepted request is answered before the process exits; SIGINT or SIGTERM instead cancels everything in flight, removes partial clones and exits.

A client configuration:

```json
{
  "mcpServers": {
    "cryptosweep": {
      "command": "node",
      "args": ["/absolute/path/to/cryptosweep/dist/mcp.js"],
      "env": { "CRYPTOSWEEP_MCP_ROOT": "/absolute/path/to/the/code/to/scan" }
    }
  }
}
```

`integrations/urfael/` packages the server as an [Urfael](https://github.com/maximilliangrand/urfael) plugin.

## Network behaviour

cryptosweep makes network connections only in these cases:

- **TLS scan of a host.** The name is resolved once, every address is checked by the SSRF guard, and every connection goes to one of those vetted addresses (the original name is sent as SNI). A scan makes one handshake, one legacy retry if the server refuses the first at the TLS layer, and one handshake per ML-KEM group the local OpenSSL supports (up to five). No application data is sent.
- **Clone of a GitHub repository.** Only `https://github.com/<owner>/<repo>` by default. `github.com` is resolved and vetted before a temporary directory exists, and git is pinned to that address. git runs without a shell, with credential helpers, hooks, symlinks, submodules, redirects and non-HTTPS protocols disabled, an allowlisted environment (`PATH`, proxy and CA variables), `--depth 1`, a 120 second deadline, a 512 MiB download cap and a 1 GiB / 250,000-file checkout cap. `--allow-any-git-host` (CLI only) allows other HTTPS and SSH remotes, still through the guard.
- **`--advisories`**: one batched POST to `api.osv.dev` (see above).

Scans of local directories make no network requests unless `--advisories` is given. There is no telemetry.

The SSRF guard refuses loopback, private (RFC 1918), CGNAT, link-local and cloud-metadata, documentation, benchmarking, multicast, reserved and the other IANA special-purpose IPv4 ranges; for IPv6 it allows only global unicast, looks inside IPv4-mapped, IPv4-translated, NAT64 (`64:ff9b::/96`) and 6to4 addresses, and blocks the documentation and other special-purpose ranges. It fails closed: a name that does not resolve, a resolver answer that is not an IP address, and a numeric host written in any form other than a canonical dotted quad (`0177.0.0.1`, `0x7f.1`, `2130706433`) are refused. `--allow-private` (CLI) or `CRYPTOSWEEP_MCP_ALLOW_PRIVATE` (MCP) lifts the range check for local testing; the resolve-once pinning still applies, to TLS connections and git clones alike.

## CLI reference

```
cryptosweep scan <target> [options]
cryptosweep version
cryptosweep help
```

| Option | Description | Default |
| --- | --- | --- |
| `--out <file>` | Write the JSON report | |
| `--md <file>` | Write the Markdown report | |
| `--cbom <file>` | Write a CycloneDX 1.6 CBOM | |
| `--sarif <file>` | Write a SARIF 2.1.0 log | |
| `--html <file>` | Write the self-contained HTML report | |
| `--risk <file>` | Write the risk model as JSON | |
| `--fail-on <severity>` | Exit 2 if any finding is at or above `critical`, `high`, `medium`, `low` or `info` | off |
| `--data-class <class>` | Data class for the risk model (see the table above) | `general` |
| `--crqc-year <year>` | Assumed CRQC year, 2020 to 2100 | 2035 |
| `--migration-years <years>` | One migration time for every asset, greater than 0 and at most 50 | 3 (key establishment), 5 (signatures) |
| `--port <port>` | TLS port, 1 to 65535 (TLS targets only) | 443 or the port in the target |
| `--timeout <ms>` | TLS handshake timeout, up to 600000 (TLS targets only) | 10000 |
| `--allow-private` | Allow non-public addresses (localhost, RFC 1918) | off |
| `--allow-any-git-host` | Allow clones from HTTPS hosts other than github.com and from SSH remotes | off |
| `--advisories` | Look up known CVEs for flagged, pinned dependencies on OSV.dev (directory and repository targets only) | off |

Two output flags may not name the same file.

## Library use

The package can be used as a library from a local checkout (for example `pnpm add /path/to/cryptosweep` after building it):

```ts
import { assessRisk, buildReport, defaultProfile, scanTarget, toCbom, toSarif } from "cryptosweep";

const findings = await scanTarget("./my-service");
const report = buildReport("./my-service", findings);
const risk = assessRisk(report.target, report.findings, defaultProfile(report.scanned_at, { dataClassId: "medical-phi" }));
const cbom = toCbom(report);
```

The package exports the scanners (`scanTls`, `scanSource`, `scanDeps`, `scanContent`, `analyzeTls`), the orchestrator (`classifyTarget`, `scanTarget`), the SSRF guard (`resolveAllowedAddress`), the hardened clone (`cloneRepository`), the rule catalogue (`SOURCE_RULES`) and registry (`REGISTRY`), the risk engine and every output format, with TypeScript types.

## Limitations

- The source scanner finds the APIs listed above and nothing else. Other libraries, languages (C, C++, C#, Rust, Ruby, PHP, Swift), configuration files (OpenSSL, nginx, SSH), cryptography built from lower-level primitives, and keys held in KMS or HSMs are not seen. Regex matches in Python, Go and the JVM do not resolve imports or scopes.
- The dependency registry covers 31 libraries. A library it does not list produces no finding, and a Go, Maven, Gradle, Ruby or PHP dependency is only reported as unparsed coverage.
- Version-aware matching exists only for the two registry entries with a `fixedIn`; other entries are flagged at every version. A manifest range that admits releases on both sides of `fixedIn` is not resolved against a lockfile elsewhere in the tree; it is reported at `low` confidence.
- MD5/SHA-1 role inference reads names, not data flow: in JavaScript and TypeScript the names around the call and its variable's next uses, elsewhere only the match's own line. A weak hash with no telling name is rated `medium` and act-now.
- The CNSA 2.0 obligation judges public-key parameter sets only; the AES-256 and SHA-384 symmetric requirements, and CNSA 2.0's per-category deadlines, are not assessed.
- The HTML viewer is committed as a generated, base64-encoded module (`src/output/viewer-shell.ts`, about 1.5 MB) with React and Blueprint inlined. It is reproducible from the lockfile (CI rebuilds it and fails on any difference), but software-composition-analysis tools that read `package.json` see React and Blueprint only as devDependencies, not as code shipped inside `--html` reports.
- The TLS scan observes one client offer. It does not enumerate every protocol version and cipher suite a server accepts, does not check revocation, and says nothing about other services on the host.
- The post-quantum probe needs OpenSSL 3.5 or later in the scanning Node.js build.
- A GitHub clone fails if the local resolver cannot resolve `github.com` (for example on a proxy-only network), and a renamed repository does not clone, because redirects are disabled.
- The risk model is a planning aid built on stated assumptions (the CRQC year, migration times, data horizons). It is not a prediction, a compliance determination or legal advice.
- A cryptosweep report is an inventory to start from, not a substitute for a review by someone who knows the system and its cryptography.

## Development

```bash
pnpm install --frozen-lockfile
pnpm build       # regenerates src/output/viewer-shell.ts, then bundles with tsup
pnpm typecheck   # src/, tests/ and viewer/
pnpm lint
pnpm test
```

CI runs these on Node.js 22 and 26 and fails if the build changes any committed file. See [CONTRIBUTING.md](CONTRIBUTING.md) for the layout, the registry rules and the test conventions, [CHANGELOG.md](CHANGELOG.md) for what changed in each release, and [SECURITY.md](SECURITY.md) for how to report a vulnerability privately.

## License

MIT, see [LICENSE](LICENSE). Built by [maximilliangrand](https://github.com/maximilliangrand).
