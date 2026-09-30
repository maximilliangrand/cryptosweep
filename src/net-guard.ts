/**
 * SSRF guard for scan targets.
 *
 * cryptosweep connects to user-supplied hosts. When it runs as (or behind) a
 * service, an attacker could point it at internal infrastructure, cloud
 * metadata endpoints, loopback admin panels, RFC 1918 hosts, to exfiltrate
 * data or map the network. This module resolves a target and refuses addresses
 * that are not publicly routable, unless the caller explicitly opts in (which
 * is reasonable for local development against `localhost`).
 *
 * The guard fails closed: a name that does not resolve, an address it cannot
 * parse, and a numeric host written in any form other than a canonical dotted
 * quad are all refused rather than waved through.
 */
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

/** An address a vetted host resolved to, in the form `net`/`tls` connect accepts. */
export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

/**
 * Parse a canonical dotted-quad IPv4 string (`127.0.0.1`) into four octets, or
 * null. Anything else — leading zeros, hex, fewer than four parts, a bare
 * integer — is rejected: those forms mean different addresses to different
 * parsers (`0177.0.0.1` is 177.0.0.1 to `Number()` but 127.0.0.1 to glibc's
 * inet_aton), so the guard never interprets them.
 */
function parseIpv4(ip: string): [number, number, number, number] | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^(?:0|[1-9]\d{0,2})$/.test(part)) return null;
    const value = Number(part);
    if (value > 255) return null;
    octets.push(value);
  }
  return octets as [number, number, number, number];
}

function ipv4ToInt(octets: readonly number[]): number {
  const [a = 0, b = 0, c = 0, d = 0] = octets;
  return ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
}

/**
 * IPv4 blocks from the IANA special-purpose registry that are not safe or not
 * meaningful to reach from a server context.
 */
const BLOCKED_IPV4: ReadonlyArray<readonly [string, number]> = [
  ["0.0.0.0", 8], // "this network", incl. the unspecified address
  ["10.0.0.0", 8], // private
  ["100.64.0.0", 10], // CGNAT shared address space
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link-local, incl. 169.254.169.254 cloud metadata
  ["172.16.0.0", 12], // private
  ["192.0.0.0", 24], // IETF protocol assignments, incl. 192.0.0.192 (Oracle Cloud metadata)
  ["192.0.2.0", 24], // documentation (TEST-NET-1)
  ["192.88.99.0", 24], // deprecated 6to4 relay anycast
  ["192.168.0.0", 16], // private
  ["198.18.0.0", 15], // benchmarking
  ["198.51.100.0", 24], // documentation (TEST-NET-2)
  ["203.0.113.0", 24], // documentation (TEST-NET-3)
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved, incl. 255.255.255.255 limited broadcast
];

const BLOCKED_IPV4_RANGES = BLOCKED_IPV4.map(([base, bits]) => {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { network: (ipv4ToInt(parseIpv4(base) ?? []) & mask) >>> 0, mask };
});

/** True for four IPv4 octets that are not safe to reach from a server context. */
function isBlockedIpv4Octets(octets: readonly number[]): boolean {
  const value = ipv4ToInt(octets);
  return BLOCKED_IPV4_RANGES.some(({ network, mask }) => ((value & mask) >>> 0) === network);
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

/** True if `bytes` starts with the first `bits` bits of `prefix`. */
function hasPrefix(bytes: readonly number[], prefix: readonly number[], bits: number): boolean {
  const whole = Math.floor(bits / 8);
  for (let i = 0; i < whole; i += 1) if (bytes[i] !== prefix[i]) return false;
  const remainder = bits % 8;
  if (remainder === 0) return true;
  const mask = (0xff << (8 - remainder)) & 0xff;
  return ((bytes[whole] ?? 0) & mask) === ((prefix[whole] ?? 0) & mask);
}

function ipv6Prefix(text: string, bits: number): { bytes: number[]; bits: number } {
  return { bytes: parseIpv6(text) ?? [], bits };
}

/** IPv6 prefixes whose last four bytes are the IPv4 address the kernel really connects to. */
const IPV4_EMBEDDING_IPV6 = [
  ipv6Prefix("::ffff:0:0", 96), // IPv4-mapped
  ipv6Prefix("::ffff:0:0:0", 96), // IPv4-translated (SIIT)
  ipv6Prefix("64:ff9b::", 96), // NAT64 well-known prefix
];

/** 6to4 embeds the IPv4 endpoint in bytes 2..5. */
const SIX_TO_FOUR = ipv6Prefix("2002::", 16);

/** Only global unicast is publicly routable; everything outside 2000::/3 is refused. */
const GLOBAL_UNICAST = ipv6Prefix("2000::", 3);

/** Special-purpose blocks carved out of global unicast that are not globally reachable. */
const NON_GLOBAL_IPV6 = [
  ipv6Prefix("2001::", 23), // IETF protocol assignments, incl. Teredo 2001::/32 and benchmarking
  ipv6Prefix("2001:db8::", 32), // documentation
  ipv6Prefix("3fff::", 20), // documentation (RFC 9637)
];

/**
 * True for an IPv6 address that is not safe to reach. Every IPv4-carrying form
 * (IPv4-mapped, IPv4-translated, NAT64, 6to4) is unwrapped and classified by
 * the IPv4 rules, because that is the address the kernel will actually connect
 * to. Everything outside global unicast 2000::/3 is refused outright: that
 * covers ::/128, ::1, the deprecated IPv4-compatible ::/96, the local-use NAT64
 * prefix 64:ff9b:1::/48 (not globally reachable by definition, and its IPv4
 * offset depends on the operator's prefix length), 100::/64 discard,
 * fc00::/7 unique-local, fe80::/10 link-local, fec0::/10 site-local and
 * ff00::/8 multicast.
 */
function isBlockedIpv6(ip: string): boolean {
  const bytes = parseIpv6(ip);
  if (!bytes) return true; // unparseable: fail closed rather than guess
  if (IPV4_EMBEDDING_IPV6.some((p) => hasPrefix(bytes, p.bytes, p.bits))) {
    return isBlockedIpv4Octets(bytes.slice(12));
  }
  if (hasPrefix(bytes, SIX_TO_FOUR.bytes, SIX_TO_FOUR.bits)) return isBlockedIpv4Octets(bytes.slice(2, 6));
  if (!hasPrefix(bytes, GLOBAL_UNICAST.bytes, GLOBAL_UNICAST.bits)) return true;
  return NON_GLOBAL_IPV6.some((p) => hasPrefix(bytes, p.bytes, p.bits));
}

/**
 * True if an already-resolved IP address is not safe to reach from a server.
 * Anything that is not a canonical IPv4 or a parseable IPv6 address is treated
 * as blocked.
 */
export function isBlockedAddress(ip: string): boolean {
  if (ip.includes(":")) return isBlockedIpv6(ip);
  const octets = parseIpv4(ip);
  return octets ? isBlockedIpv4Octets(octets) : true;
}

/**
 * True for a host that a WHATWG URL parser, and inet_aton(3) as used by glibc
 * and musl getaddrinfo, would read as an IPv4 number: its last label is
 * decimal, octal or hex digits (`127.1`, `0177.0.0.1`, `0x7f000001`,
 * `2130706433`). No real top-level domain is numeric, so nothing legitimate is
 * lost by refusing these.
 */
function looksNumeric(host: string): boolean {
  const labels = host.split(".");
  if (labels.length > 1 && labels.at(-1) === "") labels.pop();
  return /^(?:\d+|0x[0-9a-f]*)$/i.test(labels.at(-1) ?? "");
}

function describeLookupError(err: unknown): string {
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  if (code) return code;
  return err instanceof Error && err.message ? err.message : "lookup failed";
}

/**
 * Resolve `host` and return every address it resolves to, after checking each
 * one. Throws if any address is not publicly routable (unless `allowPrivate`),
 * if the name does not resolve, or if the host is a non-canonical numeric form.
 *
 * Callers that open a connection should connect to one of the returned
 * addresses (passing the name separately, e.g. as TLS `servername`) rather than
 * the name itself: resolving again at connect time would let a DNS-rebinding
 * name answer with a public address here and a private one there.
 */
export async function resolveAllowedAddress(host: string, allowPrivate = false): Promise<ResolvedAddress[]> {
  const bare = host.replace(/^\[(.*)\]$/, "$1"); // strip IPv6 brackets
  if (bare.length === 0) throw new Error("Refusing to scan an empty host");

  const family = isIP(bare);
  if (family === 4 || family === 6) {
    if (!allowPrivate && isBlockedAddress(bare)) throw new Error(`Refusing to scan non-public address: ${host}`);
    return [{ address: bare, family }];
  }
  if (bare.includes(":")) throw new Error(`Refusing to scan ${host}: not a valid IPv6 address`);
  if (looksNumeric(bare)) {
    throw new Error(
      `Refusing to scan ${host}: numeric IPv4 hosts must be written as a canonical dotted quad (for example 192.0.2.1).`,
    );
  }

  let answers: { address: string; family: number }[];
  try {
    answers = await lookup(bare, { all: true });
  } catch (err) {
    throw new Error(`Refusing to scan ${host}: DNS resolution failed (${describeLookupError(err)})`, {
      cause: err,
    });
  }
  if (answers.length === 0) throw new Error(`Refusing to scan ${host}: DNS returned no addresses`);

  const addresses = answers.map((a): ResolvedAddress => ({ address: a.address, family: a.family === 6 ? 6 : 4 }));
  if (!allowPrivate) {
    const blocked = addresses.find((a) => isBlockedAddress(a.address));
    if (blocked) {
      throw new Error(
        `Refusing to scan ${host}: resolves to non-public address ${blocked.address}. Pass --allow-private to override.`,
      );
    }
  }
  return addresses;
}

/**
 * Throw unless `host` resolves only to publicly routable addresses. A thin
 * wrapper over {@link resolveAllowedAddress} for callers that only need the
 * verdict; with `allowPrivate` it checks nothing, as before.
 */
export async function assertTargetAllowed(host: string, allowPrivate = false): Promise<void> {
  if (allowPrivate) return;
  await resolveAllowedAddress(host, false);
}
