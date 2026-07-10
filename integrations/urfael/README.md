# cryptosweep as an Urfael capability

This wires cryptosweep into [Urfael](https://github.com/Grandillionaire/urfael) as a
capability-scoped, sandboxed MCP plugin. Once enabled, Urfael's brain gains two tools:

- `mcp_cryptosweep_scan` — scan a target (hostname/URL, GitHub `owner/repo`, or a local
  path) for quantum-vulnerable cryptography and get back the inventory plus a
  harvest-now-decrypt-later (Mosca-clock) risk assessment.
- `mcp_cryptosweep_data_classes` — list the confidentiality data classes the risk model
  understands (legal, medical, financial, and so on).

So you can ask Urfael things like: "scan my vault for quantum-vulnerable crypto as
legal-privileged data" or "check what crypto stripe.com is using."

## Prerequisites

1. Build cryptosweep so `dist/mcp.js` exists:
   ```
   cd /path/to/cryptosweep && pnpm install && pnpm build
   ```
2. Have Urfael installed with its daemon running (`urfael` on your PATH).

## Point the manifest at your build

`plugin.json` runs the server with `["node", "<path>/dist/mcp.js"]`. Edit the `entry.cmd`
path in `plugin.json` if your cryptosweep checkout is not at
`/absolute/path/to/cryptosweep`.

## Install and enable

Urfael never auto-grants anything. Inspect it, install it disabled, then enable it:

```
urfael plugin scan   integrations/urfael/plugin.json     # static safety preview
urfael plugin install integrations/urfael/plugin.json    # writes it DISABLED (0600)
urfael plugin enable cryptosweep                          # attaches the MCP server
urfael plugin list                                        # confirm it is enabled
```

The manifest is validated by Urfael's own `pluginhub` parser (schema `urfael.plugin/v1`)
and passes its static scan clean.

## Security notes (read these)

- This is a `brain.tools`-only plugin, so it enables today. It declares no host
  capabilities, which means in Urfael's current release its MCP server runs
  **unconfined** (a normal local process with your privileges, not a `--network none`
  Docker cell). Urfael will tell you this at install time. That is acceptable here only
  because it is your own audited code. Do not enable a plugin you would not run yourself.
- Being unconfined is also what lets `scan` reach the filesystem (to read source and
  dependency manifests) and the network (TLS host posture, and the opt-in OSV CVE
  lookup). cryptosweep enforces its own SSRF guard, so it refuses to connect to loopback
  or private addresses unless explicitly told to.
- When Urfael's host-capability tier (the cell + broker) lands, switch to a confined,
  least-privilege grant by adding a `capabilities` block to `plugin.json`, for example:
  ```json
  "capabilities": {
    "fs":  [{ "mode": "read", "path": "/", "why": "scan vault source + dependency manifests" }],
    "net": [{ "host": "api.osv.dev", "ports": [443], "why": "opt-in known-CVE cross-reference" }],
    "brain": { "tools": [ ... ] }
  }
  ```
  Note Urfael's network grant is an exact-FQDN allowlist, so to scan a specific host over
  TLS in confined mode you add that host's FQDN to `net`.
