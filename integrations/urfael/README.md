# cryptosweep as an Urfael capability

This wires cryptosweep into [Urfael](https://github.com/maximilliangrand/urfael) as a
capability-scoped MCP plugin. Once enabled, Urfael's brain gains two tools:

- `mcp_cryptosweep_scan`: scan a target (hostname/URL, public GitHub `owner/repo`, or a
  directory under the configured root) for quantum-vulnerable cryptography and get back
  the inventory, a harvest-now-decrypt-later (Mosca-clock) risk assessment and what the
  scan covered. Optional arguments: `dataClass`, `crqcYear`, `migrationYears`.
- `mcp_cryptosweep_data_classes`: list the confidentiality data classes the risk model
  understands (legal, medical, government, financial, and so on).

So you can ask Urfael things like: "scan my vault for quantum-vulnerable crypto as
legal-privileged data" or "check what crypto example.com's TLS endpoint uses."

## Prerequisites

1. Build cryptosweep so `dist/mcp.js` exists (Node.js 22 or later; the TLS
   post-quantum probe also needs a Node.js build with OpenSSL 3.5 or later):
   ```
   cd /path/to/cryptosweep && pnpm install --frozen-lockfile && pnpm build
   ```
2. Have Urfael installed with its daemon running (`urfael` on your PATH).

## Point the manifest at your build

`plugin.json` runs the server with `["node", "/absolute/path/to/cryptosweep/dist/mcp.js"]`.
Edit that `entry.cmd` path to the absolute path of your own cryptosweep checkout (Urfael
runs the entry as a bare argv with no shell expansion, so it must be a literal path, not
`~` or `$HOME`).

## Install and enable

Urfael never auto-grants anything. Inspect it, install it disabled, then enable it:

```
urfael plugin scan   integrations/urfael/plugin.json     # static safety preview
urfael plugin install integrations/urfael/plugin.json    # writes it DISABLED (0600)
urfael plugin enable cryptosweep                          # attaches the MCP server
urfael plugin list                                        # confirm it is enabled
```

The manifest is written for Urfael's `pluginhub` parser (schema `urfael.plugin/v1`).

## Security notes (read these)

- This is a `brain.tools`-only plugin. It declares no host capabilities, which means in
  Urfael's current release its MCP server runs **unconfined** (a normal local process
  with your privileges, not a `--network none` Docker cell). Urfael will tell you this
  at install time. Do not enable a plugin you would not run yourself.
- Being unconfined is also what lets `scan` read the filesystem (source and dependency
  manifests) and reach the network (TLS handshakes, shallow clones of public GitHub
  repositories, and the opt-in OSV CVE lookup). An MCP server acts on whatever text the
  brain has been fed, so cryptosweep never lets a tool argument widen what a scan can
  reach. Only the operator can, through the server's environment:
  - **Filesystem root.** Filesystem targets must live under `CRYPTOSWEEP_MCP_ROOT`,
    checked after resolving symlinks, so a link inside the root cannot point out of it.
    If it is unset, the server's working directory is used, unless that is `/`, your
    home directory or an ancestor of it, in which case every filesystem scan is refused.
    Set it to the tree you actually want scannable:
    ```
    "entry": { "transport": "stdio", "cmd": ["node", "/absolute/path/to/cryptosweep/dist/mcp.js"],
               "env": { "CRYPTOSWEEP_MCP_ROOT": "/absolute/path/to/your/vault" } }
    ```
  - **SSRF guard.** Loopback, RFC 1918, link-local, CGNAT, cloud-metadata and the other
    special-purpose addresses are refused by default, including names that resolve to
    them; each name is resolved once and every connection goes to a vetted address, so
    DNS rebinding cannot redirect a scan. The operator can lift the range check with
    `CRYPTOSWEEP_MCP_ALLOW_PRIVATE=1`; a tool argument cannot.
  - **OSV lookups** are off unless the operator sets `CRYPTOSWEEP_MCP_ADVISORIES=1`
    (they send flagged dependency names and versions to api.osv.dev). The tool has no
    argument that turns them on.
  - **Clones** are limited to `https://github.com/<owner>/<repo>`, through the same guard,
    with git's credential helpers, hooks, redirects and symlinks disabled and size and
    time limits applied.
  - Text from the scanned target (file names, certificate fields) has control and
    bidirectional characters replaced before it reaches the brain, and at most two scans
    run at once.
- When Urfael's host-capability tier (the cell + broker) lands, switch to a confined,
  least-privilege grant by adding a `capabilities` block to `plugin.json`, for example:
  ```json
  "capabilities": {
    "fs":  [{ "mode": "read", "path": "/absolute/path/to/your/vault", "why": "scan source + dependency manifests" }],
    "net": [{ "host": "github.com", "ports": [443], "why": "shallow clones of public repositories" },
            { "host": "api.osv.dev", "ports": [443], "why": "opt-in known-CVE cross-reference" }],
    "brain": { "tools": [ ... ] }
  }
  ```
  Urfael's network grant is an exact-FQDN allowlist, so to scan a specific host over
  TLS in confined mode you add that host's FQDN to `net`.
