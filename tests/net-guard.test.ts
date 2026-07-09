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

  it("allows public addresses", () => {
    for (const ip of ["8.8.8.8", "1.1.1.1", "172.32.0.1", "192.169.0.1", "2606:4700:4700::1111"]) {
      expect(isBlockedAddress(ip), ip).toBe(false);
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
