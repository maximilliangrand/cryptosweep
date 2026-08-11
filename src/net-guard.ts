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

/** True for four IPv4 octets that are not safe to reach from a server context. */
function isBlockedIpv4Octets(octets: readonly number[]): boolean {
  const [a = 0, b = 0] = octets;
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

/** True for an IPv4 address that is not safe to reach from a server context. */
function isBlockedIpv4(ip: string): boolean {
  const octets = parseIpv4(ip);
  if (!octets) return false;
  return isBlockedIpv4Octets(octets);
}

/**
 * Parse any textual IPv6 form into its canonical 16 bytes, or null if it is not
 * a valid address. Classification must happen on the bytes, never on the text:
 * `::ffff:7f00:1`, `::ffff:127.0.0.1` and `0:0:0:0:0:ffff:7f00:0001` are the
 * same address, and a textual pattern only ever recognizes one of them.
 */
function parseIpv6(ip: string): number[] | null {
  const addr = (ip.toLowerCase().split("%")[0] ?? ip).trim(); // strip zone id
  if (addr.length === 0 || !addr.includes(":")) return null;

  // A trailing dotted-quad (::ffff:1.2.3.4) is rewritten to the two hex groups
  // it denotes, so the rest of the parse only ever handles hex groups.
  let hexPart = addr;
  const lastColon = addr.lastIndexOf(":");
  const trailing = addr.slice(lastColon + 1);
  if (trailing.includes(".")) {
    const octets = parseIpv4(trailing);
    if (!octets) return null;
    const [a, b, c, d] = octets;
    hexPart = `${addr.slice(0, lastColon + 1)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }

  const halves = hexPart.split("::");
  if (halves.length > 2) return null;
  const toGroups = (part: string): number[] | null => {
    if (part.length === 0) return [];
    const groups: number[] = [];
    for (const chunk of part.split(":")) {
      if (!/^[0-9a-f]{1,4}$/.test(chunk)) return null;
      groups.push(Number.parseInt(chunk, 16));
    }
    return groups;
  };
  const head = toGroups(halves[0] ?? "");
  const rest = halves.length === 2 ? toGroups(halves[1] ?? "") : null;
  if (!head || (halves.length === 2 && !rest)) return null;

  const groupBytes = (groups: number[]): number[] => groups.flatMap((g) => [g >> 8, g & 0xff]);
  const headBytes = groupBytes(head);
  if (halves.length === 1) return headBytes.length === 16 ? headBytes : null;

  const restBytes = groupBytes(rest ?? []);
  const missing = 16 - headBytes.length - restBytes.length;
  if (missing < 1) return null; // "::" must stand for at least one zero group
  return [...headBytes, ...new Array<number>(missing).fill(0), ...restBytes];
}

/** True if the first `count` bytes are all zero. */
function zeroPrefix(bytes: readonly number[], count: number): boolean {
  for (let i = 0; i < count; i += 1) if (bytes[i] !== 0) return false;
  return true;
}

/**
 * True for an IPv6 address that is not safe to reach. Every IPv4-carrying form
 * (IPv4-mapped, IPv4-compatible, NAT64, 6to4) is unwrapped and classified by the
 * IPv4 rules, because that is the address the kernel will actually connect to.
 */
function isBlockedIpv6(ip: string): boolean {
  const bytes = parseIpv6(ip);
  if (!bytes) return true; // unparseable: fail closed rather than guess
  // ::/96 covers ::, ::1 and the deprecated IPv4-compatible form; ::ffff:0:0/96
  // is IPv4-mapped. Both put the real destination in the last four bytes.
  if (zeroPrefix(bytes, 10) && ((bytes[10] === 0 && bytes[11] === 0) || (bytes[10] === 0xff && bytes[11] === 0xff))) {
    return isBlockedIpv4Octets(bytes.slice(12));
  }
  // NAT64 well-known prefix 64:ff9b::/96.
  if (bytes[0] === 0x00 && bytes[1] === 0x64 && bytes[2] === 0xff && bytes[3] === 0x9b && zeroPrefix(bytes.slice(4), 8)) {
    return isBlockedIpv4Octets(bytes.slice(12));
  }
  // 6to4 (2002::/16) embeds the IPv4 endpoint in bytes 2..5.
  if (bytes[0] === 0x20 && bytes[1] === 0x02) return isBlockedIpv4Octets(bytes.slice(2, 6));
  if (bytes[0] === 0xfe && ((bytes[1] ?? 0) & 0xc0) === 0x80) return true; // link-local fe80::/10
  if (((bytes[0] ?? 0) & 0xfe) === 0xfc) return true; // unique-local fc00::/7
  if (bytes[0] === 0xff) return true; // multicast
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
