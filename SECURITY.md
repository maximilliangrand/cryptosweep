# Security policy

cryptosweep reads untrusted input by design: arbitrary TLS hosts, cloned
repositories, dependency manifests, and, through the MCP server, tool
arguments written by a language model. A bug that lets that input reach
somewhere it should not is a security issue, and reports are welcome.

## Supported versions

Only the latest release (currently 0.2.x) and the `main` branch receive fixes.

## What counts

Report privately if you find a way to make cryptosweep:

- connect to or clone from a non-public address without `--allow-private` /
  `CRYPTOSWEEP_MCP_ALLOW_PRIVATE` (an SSRF guard bypass, DNS rebinding, a
  numeric-host trick, a redirect);
- read, reveal the existence of, or scan files outside `CRYPTOSWEEP_MCP_ROOT`
  through the MCP server;
- run code, or hand git a credential, hook, transport or config it should not
  have;
- hang, exhaust memory or disk, or pin the CPU on a crafted file, manifest,
  certificate or server (catastrophic regex backtracking, unbounded reads);
- emit attacker-controlled terminal escapes, Markdown or HTML into its output;
- send data to a third party without the documented opt-in (`--advisories`).

A wrong verdict (a false positive or a missed primitive) is a normal bug:
open a public issue for it.

## How to report

Do not put details in a public issue or pull request.

- If the repository's **Security** tab offers **Report a vulnerability**
  (GitHub private vulnerability reporting), use it.
- Otherwise, open an issue titled `Security contact request`, with no
  description of the problem, and the maintainer
  ([maximilliangrand](https://github.com/maximilliangrand)) will reply with a
  private channel.

Include the cryptosweep version or commit, the Node.js and OpenSSL versions
(`node -p "process.version + ' ' + process.versions.openssl"`), the command or
MCP call, and a minimal reproduction. There is no bug bounty, and no fixed
response time is promised; fixes are credited in the CHANGELOG unless you ask
otherwise.
