import { afterEach, describe, expect, it, vi } from "vitest";
import { assertTargetAllowed, isBlockedAddress, resolveAllowedAddress } from "../src/net-guard";

// The resolver is stubbed so every hostname test is offline and deterministic.
const dns = vi.hoisted(() => ({ lookup: vi.fn() }));
vi.mock("node:dns/promises", () => ({ lookup: dns.lookup }));

afterEach(() => {
  dns.lookup.mockReset();
});

describe("isBlockedAddress", () => {
  it("blocks loopback, private, link-local, CGNAT, and metadata addresses", () => {
    for (const ip of [
      "127.0.0.1",
      "10.0.0.5",
      "192.168.1.1",
      "172.16.0.1",
      "172.31.255.255",
      "169.254.169.254", // cloud metadata
      "100.64.0.1", // CGNAT
      "0.0.0.0",
      "::1",
      "fe80::1",
      "fc00::abcd",
      "::ffff:127.0.0.1", // IPv4-mapped loopback
    ]) {
      expect(isBlockedAddress(ip), ip).toBe(true);
    }
  });

  it("blocks every textual spelling of the same non-public IPv6 address", () => {
    for (const ip of [
      "::ffff:7f00:1", // IPv4-mapped loopback in hex-quartet form
      "::ffff:a9fe:a9fe", // IPv4-mapped 169.254.169.254 (cloud metadata)
      "0:0:0:0:0:0:0:1", // uncompressed loopback
      "0000:0000:0000:0000:0000:ffff:7f00:0001", // fully padded IPv4-mapped loopback
      "::0.0.0.0", // IPv4-compatible unspecified
      "::7f00:1", // IPv4-compatible loopback
      "64:ff9b::a9fe:a9fe", // NAT64 well-known prefix onto metadata
      "2002:7f00:1::1", // 6to4 wrapping 127.0.0.1
      "FE80::1", // uppercase link-local
      "fe80::1%en0", // link-local with a zone id
    ]) {
      expect(isBlockedAddress(ip), ip).toBe(true);
    }
  });

  it("allows public addresses", () => {
    for (const ip of [
      "8.8.8.8",
      "1.1.1.1",
      "172.32.0.1",
      "192.169.0.1",
      "2606:4700:4700::1111",
      "::ffff:8.8.8.8", // IPv4-mapped public address stays reachable
      "::ffff:808:808", // the same address, hex-quartet form
      "2002:808:808::1", // 6to4 wrapping a public IPv4
    ]) {
      expect(isBlockedAddress(ip), ip).toBe(false);
    }
  });

  it("blocks the rest of the IANA special-purpose IPv4 registry", () => {
    for (const ip of [
      "0.1.2.3", // 0.0.0.0/8
      "100.127.255.255", // top of CGNAT 100.64/10
      "169.254.0.1", // link-local
      "192.0.0.192", // 192.0.0.0/24, Oracle Cloud metadata
      "192.0.0.8",
      "192.0.2.1", // TEST-NET-1
      "198.51.100.1", // TEST-NET-2
      "203.0.113.1", // TEST-NET-3
      "198.18.0.1", // benchmarking 198.18/15
      "198.19.255.255",
      "192.88.99.1", // deprecated 6to4 relay anycast
      "224.0.0.1", // multicast
      "239.255.255.250",
      "240.0.0.1", // reserved
      "255.255.255.255", // limited broadcast
    ]) {
      expect(isBlockedAddress(ip), ip).toBe(true);
    }
    for (const ip of ["100.63.255.255", "100.128.0.0", "198.17.255.255", "198.20.0.0", "192.0.1.1", "223.255.255.255"]) {
      expect(isBlockedAddress(ip), ip).toBe(false);
    }
  });

  it("blocks non-global IPv6 ranges and unwraps every IPv4-embedding prefix", () => {
    for (const ip of [
      "::", // unspecified
      "::8.8.8.8", // deprecated IPv4-compatible form is not routed
      "64:ff9b:1::a00:1", // local-use NAT64 (RFC 8215), blocked outright
      "64:ff9b:1::808:808",
      "64:ff9b::c000:2c0", // NAT64 onto 192.0.0.192
      "::ffff:0:a00:1", // IPv4-translated (SIIT) 10.0.0.1
      "2002:c000:2c0::1", // 6to4 onto 192.0.0.192
      "100::1", // discard-only
      "fec0::1", // deprecated site-local
      "2001:0:4136:e378:8000:63bf:80ff:fffe", // Teredo
      "2001:2::1", // benchmarking
      "2001:db8::1", // documentation
      "3fff::1", // documentation (RFC 9637)
      "ff02::1", // multicast
      "5f00::1", // SRv6 SIDs, outside global unicast
    ]) {
      expect(isBlockedAddress(ip), ip).toBe(true);
    }
    for (const ip of ["64:ff9b::808:808", "::ffff:0:808:808", "2001:4860:4860::8888", "2a00:1450:4001::1"]) {
      expect(isBlockedAddress(ip), ip).toBe(false);
    }
  });

  it("treats anything that is not a canonical IP as blocked", () => {
    for (const ip of ["0177.0.0.1", "127.1", "2130706433", "0x7f.0.0.1", "example.com", ""]) {
      expect(isBlockedAddress(ip), ip).toBe(true);
    }
  });

  it("fails closed on an unparseable IPv6 literal", () => {
    for (const ip of ["::ffff:zzzz", "1:2:3", "12345::1", "::1::2"]) {
      expect(isBlockedAddress(ip), ip).toBe(true);
    }
  });
});

describe("assertTargetAllowed", () => {
  it("rejects a private IP literal target", async () => {
    await expect(assertTargetAllowed("127.0.0.1")).rejects.toThrow(/non-public/);
    await expect(assertTargetAllowed("[::1]")).rejects.toThrow(/non-public/);
  });

  it("permits a private target when explicitly allowed", async () => {
    await expect(assertTargetAllowed("127.0.0.1", true)).resolves.toBeUndefined();
  });

  it("permits a public IP literal", async () => {
    await expect(assertTargetAllowed("1.1.1.1")).resolves.toBeUndefined();
  });

  it("refuses a hostname whose DNS lookup fails instead of waving it through", async () => {
    dns.lookup.mockRejectedValue(Object.assign(new Error("getaddrinfo ENOTFOUND"), { code: "ENOTFOUND" }));
    await expect(assertTargetAllowed("nonexistent-host.invalid")).rejects.toThrow(/DNS resolution failed \(ENOTFOUND\)/);
  });

  it("refuses a hostname that resolves to a private address", async () => {
    dns.lookup.mockResolvedValue([
      { address: "93.184.215.14", family: 4 },
      { address: "10.0.0.7", family: 4 },
    ]);
    await expect(assertTargetAllowed("rebind.example")).rejects.toThrow(/resolves to non-public address 10\.0\.0\.7/);
  });
});

describe("resolveAllowedAddress", () => {
  it("returns the vetted address list so callers can pin the connection", async () => {
    dns.lookup.mockResolvedValue([
      { address: "93.184.215.14", family: 4 },
      { address: "2606:2800:21f:cb07:6820:80da:af6b:8b2c", family: 6 },
    ]);
    await expect(resolveAllowedAddress("example.com")).resolves.toEqual([
      { address: "93.184.215.14", family: 4 },
      { address: "2606:2800:21f:cb07:6820:80da:af6b:8b2c", family: 6 },
    ]);
    expect(dns.lookup).toHaveBeenCalledWith("example.com", { all: true });
  });

  it("returns an IP literal as-is without resolving it", async () => {
    await expect(resolveAllowedAddress("8.8.8.8")).resolves.toEqual([{ address: "8.8.8.8", family: 4 }]);
    await expect(resolveAllowedAddress("[2606:4700::1111]")).resolves.toEqual([{ address: "2606:4700::1111", family: 6 }]);
    expect(dns.lookup).not.toHaveBeenCalled();
  });

  it("returns private addresses only when explicitly allowed", async () => {
    dns.lookup.mockResolvedValue([{ address: "127.0.0.1", family: 4 }]);
    await expect(resolveAllowedAddress("localhost")).rejects.toThrow(/non-public/);
    await expect(resolveAllowedAddress("localhost", true)).resolves.toEqual([{ address: "127.0.0.1", family: 4 }]);
  });

  it("still fails closed on DNS errors and empty answers when private targets are allowed", async () => {
    dns.lookup.mockRejectedValueOnce(Object.assign(new Error("queryA ESERVFAIL"), { code: "ESERVFAIL" }));
    await expect(resolveAllowedAddress("flaky.example", true)).rejects.toThrow(/DNS resolution failed \(ESERVFAIL\)/);
    dns.lookup.mockResolvedValueOnce([]);
    await expect(resolveAllowedAddress("empty.example", true)).rejects.toThrow(/no addresses/);
  });

  it("refuses non-canonical numeric IPv4 forms before any resolution", async () => {
    // glibc/musl getaddrinfo read these with inet_aton: 0177.0.0.1 and 0x7f.1 are
    // 127.0.0.1 and 012.0.0.1 is 10.0.0.1, whatever the guard might think.
    for (const host of ["0177.0.0.1", "012.0.0.1", "0x7f.0.0.1", "0x7f000001", "2130706433", "127.1", "10.1", "1.2.3.4.", "01.1.1.1"]) {
      await expect(resolveAllowedAddress(host), host).rejects.toThrow(/canonical dotted quad/);
      await expect(resolveAllowedAddress(host, true), host).rejects.toThrow(/canonical dotted quad/);
    }
    expect(dns.lookup).not.toHaveBeenCalled();
  });

  it("refuses an empty host and a malformed IPv6 literal", async () => {
    await expect(resolveAllowedAddress("")).rejects.toThrow(/empty host/);
    await expect(resolveAllowedAddress("[::1::2]")).rejects.toThrow(/not a valid IPv6 address/);
    await expect(resolveAllowedAddress("example.com:443")).rejects.toThrow(/not a valid IPv6 address/);
  });
});
