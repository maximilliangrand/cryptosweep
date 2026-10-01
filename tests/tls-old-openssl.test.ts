/**
 * A runtime whose OpenSSL lacks the ML-KEM groups (Node.js 22.0 to 22.19 ship
 * OpenSSL 3.0) against a server that accepts only ML-KEM. The scan used to
 * abort with ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE, although the README said
 * the rest of the scan still runs and reports the key exchange as untested.
 * The local OpenSSL's missing groups are simulated by refusing them in
 * `createSecureContext`, the probe the scanner uses to test local support.
 */
import { readFileSync } from "node:fs";
import type { Socket } from "node:net";
import * as tls from "node:tls";
import type * as TlsModule from "node:tls";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { describeCoverage } from "../src/orchestrate";
import { scanTls } from "../src/scanners/tls";

vi.mock("node:tls", async (importOriginal) => {
  const actual = await importOriginal<typeof TlsModule>();
  return {
    ...actual,
    createSecureContext: (options?: tls.SecureContextOptions) => {
      if (/MLKEM/i.test(options?.ecdhCurve ?? "")) throw new Error("unsupported group (simulated OpenSSL 3.0)");
      return actual.createSecureContext(options);
    },
  };
});

function fixture(name: string): Buffer {
  return readFileSync(fileURLToPath(new URL(`./fixtures/tls-server/${name}`, import.meta.url)));
}

/** Whether the real runtime can run an ML-KEM-only server at all (OpenSSL 3.5+). */
function realRuntimeHasMlKem(): boolean {
  try {
    tls.createServer({ ecdhCurve: "X25519MLKEM768" }).close();
    return true;
  } catch {
    return false;
  }
}

describe("a PQ-only server scanned from a runtime without ML-KEM", () => {
  it.skipIf(!realRuntimeHasMlKem())("reports what it could not assess instead of aborting", async () => {
    const sockets = new Set<Socket>();
    const server = tls.createServer(
      { key: fixture("rsa2048-key.pem"), cert: fixture("rsa2048-cert.pem"), minVersion: "TLSv1.3", ecdhCurve: "X25519MLKEM768" },
      (socket) => socket.end(),
    );
    server.on("connection", (socket: Socket) => {
      sockets.add(socket);
      socket.on("close", () => sockets.delete(socket));
    });
    server.on("tlsClientError", () => undefined);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    try {
      const findings = await scanTls("127.0.0.1", { port, allowPrivate: true, timeoutMs: 5_000 });
      const refused = findings.find((f) => f.ruleId === "tls/handshake-refused");
      expect(refused).toMatchObject({ severity: "info", pq_status: "unknown" });
      expect(refused?.evidence).toMatch(/ERR_SSL_.*lacks X25519MLKEM768/);
      const kex = findings.find((f) => f.ruleId === "tls/hybrid-kex");
      expect(kex?.title).toMatch(/not tested: the local TLS runtime lacks ML-KEM groups/);
      const [coverage] = describeCoverage({ kind: "host", host: "127.0.0.1", port }, findings);
      expect(coverage?.complete).toBe(false);
    } finally {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
