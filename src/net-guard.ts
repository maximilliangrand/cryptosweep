/**
 * SSRF guard for scan targets.
 *
 * cryptosweep connects to user-supplied hosts. When it runs as (or behind) a
 * service, an attacker could point it at internal infrastructure, cloud
 * metadata endpoints, loopback admin panels, RFC 1918 hosts, to exfiltrate
 * data or map the network. This module resolves a target and refuses addresses
 * that are not publicly routable, unless the caller explicitly opts in (which
 * is reasonable for local development against `localhost`).
 */
import { lookup } from "node:dns/promises";

/** Parse a dotted IPv4 string into four octets, or null if it is not IPv4. */
function parseIpv4(ip: string): [number, number, number, number] | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map((p) => Number(p));
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return octets as [number, number, number, number];
}

/** True for an IPv4 address that is not safe to reach from a server context. */
function isBlockedIpv4(ip: string): boolean {
  const octets = parseIpv4(ip);
  if (!octets) return false;
  const [a, b] = octets;
  if (a === 0) return true; // "this network" / unspecified
  if (a === 10) return true; // private
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local incl. 169.254.169.254 metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT (100.64/10)
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a >= 224) return true; // multicast + reserved
  return false;
}

/** True for an IPv6 address (or IPv4-mapped IPv6) that is not safe to reach. */
function isBlockedIpv6(ip: string): boolean {
  const addr = ip.toLowerCase().split("%")[0] ?? ip; // strip zone id
  if (addr === "::1" || addr === "::") return true; // loopback / unspecified
  // IPv4-mapped (::ffff:a.b.c.d), evaluate the embedded IPv4.
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(addr);
  if (mapped?.[1]) return isBlockedIpv4(mapped[1]);
  if (/^fe[89ab]/.test(addr)) return true; // link-local fe80::/10
  if (/^f[cd]/.test(addr)) return true; // unique-local fc00::/7
  if (/^ff/.test(addr)) return true; // multicast
  return false;
}

/** True if an already-resolved IP address is not safe to reach from a server. */
export function isBlockedAddress(ip: string): boolean {
  return ip.includes(":") ? isBlockedIpv6(ip) : isBlockedIpv4(ip);
}

/**
 * Resolve `host` and throw if any resolved address is not publicly routable.
 * A hostname that resolves to a private address (DNS rebinding) is caught here
 * because we check the resolved IPs, not the name.
 */
export async function assertTargetAllowed(host: string, allowPrivate = false): Promise<void> {
  if (allowPrivate) return;
  const bare = host.replace(/^\[|\]$/g, ""); // strip IPv6 brackets
  if (parseIpv4(bare) || bare.includes(":")) {
    if (isBlockedAddress(bare)) throw new Error(`Refusing to scan non-public address: ${host}`);
    return;
  }
  let addresses: { address: string }[];
  try {
    addresses = await lookup(bare, { all: true });
  } catch {
    return; // DNS failure surfaces later as a connect error with a clearer message
  }
  const blocked = addresses.find((a) => isBlockedAddress(a.address));
  if (blocked) {
    throw new Error(
      `Refusing to scan ${host}: resolves to non-public address ${blocked.address}. Pass --allow-private to override.`,
    );
  }
}
