/**
 * DNS-rebinding hardening for the TLS path. The resolver the scanner vets
 * (`node:dns/promises`) is stubbed so each test controls what the name
 * "resolves" to; the resolver Node would use on its own at connect time
 * (`dns.lookup`) is watched, and must never be consulted.
 */
import dns from "node:dns";
import type { LookupAddress } from "node:dns";
import type * as DnsPromises from "node:dns/promises";
import { readFileSync } from "node:fs";
import type { Socket } from "node:net";
import { createServer } from "node:tls";
import type { Server } from "node:tls";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { scanTls } from "../src/scanners/tls";

const vettedLookup = vi.hoisted(() => vi.fn<(host: string, options: unknown) => Promise<LookupAddress[]>>());

vi.mock("node:dns/promises", async (importOriginal) => ({
  ...(await importOriginal<typeof DnsPromises>()),
  lookup: vettedLookup,
}));

function fixture(name: string): Buffer {
  return readFileSync(fileURLToPath(new URL(`./fixtures/tls-server/${name}`, import.meta.url)));
}

let server: Server;
let port = 0;
let connections = 0;
const clientErrors: string[] = [];
const sockets = new Set<Socket>();

beforeEach(async () => {
  connections = 0;
  server = createServer({ key: fixture("rsa2048-key.pem"), cert: fixture("rsa2048-cert.pem") }, (socket) => socket.end());
  server.on("connection", (socket: Socket) => {
    connections += 1;
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  // Probes offering a group the server refuses fail on its side as well.
  server.on("tlsClientError", (err: NodeJS.ErrnoException) => clientErrors.push(err.code ?? err.message));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  port = address && typeof address !== "string" ? address.port : 0;
});

afterEach(async () => {
  vettedLookup.mockReset();
  vi.restoreAllMocks();
  for (const socket of sockets) socket.destroy();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("TLS target resolution", () => {
  it("resolves once and connects only to the vetted address, never re-resolving the name", async () => {
    vettedLookup.mockResolvedValue([{ address: "127.0.0.1", family: 4 }]);
    const connectTimeLookup = vi.spyOn(dns, "lookup");

    // "rebind.test" does not exist (RFC 6761): any connect-time resolution of
    // the name, which is what a rebinding resolver exploits, fails the scan.
    const findings = await scanTls("rebind.test", { port, allowPrivate: true, timeoutMs: 5000 });

    expect(findings.some((f) => f.id === "CSW-TLS-001")).toBe(true);
    expect(vettedLookup).toHaveBeenCalledTimes(1);
    expect(connectTimeLookup).not.toHaveBeenCalled();
    expect(connections).toBeGreaterThan(0);
  });

  it("fails closed when the lookup fails, instead of letting the connect resolve it", async () => {
    vettedLookup.mockRejectedValue(Object.assign(new Error("queryA ENOTFOUND rebind.test"), { code: "ENOTFOUND" }));
    const connectTimeLookup = vi.spyOn(dns, "lookup");

    await expect(scanTls("rebind.test", { port, timeoutMs: 5000 })).rejects.toThrow(/Could not resolve rebind\.test \(ENOTFOUND\)/);
    expect(connectTimeLookup).not.toHaveBeenCalled();
    expect(connections).toBe(0);
  });

  it("refuses a name when any one of its addresses is non-public", async () => {
    vettedLookup.mockResolvedValue([
      { address: "93.184.215.14", family: 4 },
      { address: "127.0.0.1", family: 4 },
    ]);
    await expect(scanTls("rebind.test", { port, timeoutMs: 5000 })).rejects.toThrow(
      /Refusing to scan rebind\.test: resolves to non-public address 127\.0\.0\.1/,
    );
    expect(connections).toBe(0);
  });

  it("refuses a resolver answer that is not an IP address", async () => {
    vettedLookup.mockResolvedValue([{ address: "internal.corp", family: 0 }]);
    await expect(scanTls("rebind.test", { port, timeoutMs: 5000 })).rejects.toThrow(/usable address/);
    expect(connections).toBe(0);
  });

  it("checks IP literals directly, without a lookup", async () => {
    await expect(scanTls("127.0.0.1", { port, timeoutMs: 5000 })).rejects.toThrow(/non-public address: 127\.0\.0\.1/);
    await expect(scanTls("[::1]", { port, timeoutMs: 5000 })).rejects.toThrow(/non-public/);
    expect(vettedLookup).not.toHaveBeenCalled();
    expect(connections).toBe(0);
  });
});
