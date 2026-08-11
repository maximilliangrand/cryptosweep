import { describe, expect, it } from "vitest";
import { assertTargetAllowed, isBlockedAddress } from "../src/net-guard";

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
});
