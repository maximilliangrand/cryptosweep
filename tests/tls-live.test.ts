/**
 * Live TLS probe tests: real node:tls servers on loopback, scanned through the
 * real network path (resolution, primary handshake, per-group probes). Every
 * other TLS test injects a probe, which is how the TLS 1.2 false positive went
 * unnoticed.
 */
import { readFileSync } from "node:fs";
import type { Socket } from "node:net";
import { createPrivateKey } from "node:crypto";
import { TLSSocket, createSecureContext, createServer } from "node:tls";
import type { TlsOptions } from "node:tls";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { scanTls } from "../src/scanners/tls";
import type { Finding } from "../src/report";

function fixture(name: string): Buffer {
  return readFileSync(fileURLToPath(new URL(`./fixtures/tls-server/${name}`, import.meta.url)));
}

function runtimeSupports(check: () => unknown): boolean {
  try {
    check();
    return true;
  } catch {
    return false;
  }
}

const RSA = { key: fixture("rsa2048-key.pem"), cert: fixture("rsa2048-cert.pem") };
const HAS_MLKEM = runtimeSupports(() => createSecureContext({ ecdhCurve: "X25519MLKEM768:SecP384r1MLKEM1024:MLKEM1024" }));
const HAS_MLDSA = runtimeSupports(() => createPrivateKey(fixture("ml-dsa-65-key.pem")));
const NO_MLKEM = `local OpenSSL ${process.versions.openssl ?? "?"} has no ML-KEM TLS groups (needs 3.5+)`;
const NO_MLDSA = `local OpenSSL ${process.versions.openssl ?? "?"} cannot load ML-DSA keys (needs 3.5+)`;
const ALL_GROUPS = "X25519MLKEM768, SecP256r1MLKEM768, MLKEM768, SecP384r1MLKEM1024, MLKEM1024";

interface LiveServer {
  port: number;
  /** Connections the server has accepted so far. */
  connections: () => number;
  /** SNI names clients sent on completed handshakes. */
  servernames: () => string[];
  close: () => Promise<void>;
}

async function startServer(options: TlsOptions): Promise<LiveServer> {
  const sockets = new Set<Socket>();
  const clientErrors: string[] = [];
  const servernames: string[] = [];
  let connections = 0;
  const server = createServer(options, (socket) => {
    const sni: unknown = socket.servername;
    if (typeof sni === "string") servernames.push(sni);
    socket.end();
  });
  server.on("connection", (socket: Socket) => {
    connections += 1;
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  // A probe offering a group the server refuses ends in a handshake error on
  // the server side too; that is the behavior under test, not a failure.
  server.on("tlsClientError", (err: NodeJS.ErrnoException) => clientErrors.push(err.code ?? err.message));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("server did not bind a TCP port");
  return {
    port: address.port,
    connections: () => connections,
    servernames: () => [...servernames],
    close: () =>
      new Promise((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.close(() => resolve());
      }),
  };
}

async function scanServer(options: TlsOptions): Promise<Finding[]> {
  const server = await startServer(options);
  try {
    return await scanTls("127.0.0.1", { port: server.port, allowPrivate: true, timeoutMs: 5000 });
  } finally {
    await server.close();
  }
}

function byId(findings: Finding[], id: string): Finding {
  const finding = findings.find((f) => f.id === id);
  if (!finding) throw new Error(`expected finding ${id}, got ${findings.map((f) => `${f.id} ${f.title}`).join("; ")}`);
  return finding;
}

describe("live probe: TLS 1.2-only servers", () => {
  it("does not report hybrid support for a TLS 1.2 ECDHE server", async () => {
    const findings = await scanServer({ ...RSA, maxVersion: "TLSv1.2" });
    expect(byId(findings, "CSW-TLS-004").title).toBe("Negotiated TLSv1.2");
    expect(byId(findings, "CSW-TLS-004").pq_status).toBe("vulnerable");
    const kex = byId(findings, "CSW-TLS-005");
    expect(kex.title).not.toMatch(/supports/);
    expect(kex.title).toBe("No post-quantum key exchange: TLSv1.2 negotiated ECDHE-X25519");
    expect(kex.pq_status).toBe("vulnerable");
  });

  it("flags static-RSA key transport instead of calling it post-quantum (the audit repro)", async () => {
    // The old probe completed this handshake as TLS 1.2 AES256-GCM-SHA384 and
    // reported "Server supports hybrid post-quantum key exchange (X25519MLKEM768)".
    const findings = await scanServer({ ...RSA, maxVersion: "TLSv1.2", ciphers: "AES256-GCM-SHA384" });
    const kex = byId(findings, "CSW-TLS-005");
    expect(kex.title).toMatch(/^RSA key exchange without forward secrecy \(TLSv1\.2\)/);
    expect(kex.severity).toBe("high");
    expect(kex.pq_status).toBe("vulnerable");
    expect(kex.confidence).toBe("confirmed");
    expect(findings.some((f) => /supports .*post-quantum/.test(f.title))).toBe(false);
  });

  it("reports a TLS 1.0-only server instead of aborting the scan", async () => {
    const findings = await scanServer({ ...RSA, minVersion: "TLSv1", maxVersion: "TLSv1", ciphers: "DEFAULT:@SECLEVEL=0" });
    const protocol = byId(findings, "CSW-TLS-004");
    expect(protocol.title).toBe("Obsolete protocol negotiated (TLSv1)");
    expect(protocol.severity).toBe("high");
    expect(protocol.evidence).toMatch(/legacy/);
  });
});

describe("live probe: TLS 1.3 servers", () => {
  it("names every group it tried against an X25519-only server", async (ctx) => {
    const findings = await scanServer({ ...RSA, minVersion: "TLSv1.3", ecdhCurve: "X25519" });
    const kex = byId(findings, "CSW-TLS-005");
    if (!HAS_MLKEM) {
      expect(kex.title).toMatch(/not tested: the local TLS runtime lacks ML-KEM/);
      ctx.skip(NO_MLKEM);
    }
    expect(kex.title).toBe(`No tested post-quantum key-exchange group accepted (tried: ${ALL_GROUPS})`);
    expect(kex.pq_status).toBe("vulnerable");
    expect(kex.confidence).toBe("high");
    expect(kex.algorithm).toBe("ECDHE-X25519");
  });

  it("confirms X25519MLKEM768 from the negotiated group", async (ctx) => {
    ctx.skip(!HAS_MLKEM, NO_MLKEM);
    const findings = await scanServer({ ...RSA, minVersion: "TLSv1.3", ecdhCurve: "X25519MLKEM768" });
    const kex = byId(findings, "CSW-TLS-005");
    expect(kex.title).toBe("Server supports hybrid post-quantum key exchange (X25519MLKEM768)");
    expect(kex.pq_status).toBe("transitional");
    // Confirmed where the runtime names the negotiated group; Node 22 does not (see below).
    expect(kex.confidence).toBe(/inferred/.test(kex.evidence) ? "high" : "confirmed");
    expect(kex.recommendation).toMatch(/Not CNSA 2\.0 compliant/);
  });

  it("scans a SecP384r1MLKEM1024-only server and credits the CNSA 2.0 KEM", async (ctx) => {
    ctx.skip(!HAS_MLKEM, NO_MLKEM);
    // With Node's default groups this server failed the primary handshake and
    // the scan produced no report at all.
    const findings = await scanServer({ ...RSA, minVersion: "TLSv1.3", ecdhCurve: "SecP384r1MLKEM1024" });
    const kex = byId(findings, "CSW-TLS-005");
    expect(kex.title).toBe("Server supports hybrid post-quantum key exchange (SecP384r1MLKEM1024)");
    expect(kex.recommendation).toMatch(/parameter set CNSA 2\.0 specifies/);
  });

  it("reports a pure ML-KEM-1024 server as post-quantum safe", async (ctx) => {
    ctx.skip(!HAS_MLKEM, NO_MLKEM);
    const findings = await scanServer({ ...RSA, minVersion: "TLSv1.3", ecdhCurve: "MLKEM1024" });
    const kex = byId(findings, "CSW-TLS-005");
    expect(kex.title).toBe("Server supports post-quantum key exchange (MLKEM1024)");
    expect(kex.pq_status).toBe("safe");
  });

  it("types a served ML-DSA-65 leaf as a post-quantum key", async (ctx) => {
    ctx.skip(!HAS_MLDSA, NO_MLDSA);
    const findings = await scanServer({ key: fixture("ml-dsa-65-key.pem"), cert: fixture("ml-dsa-65-cert.pem") });
    const key = byId(findings, "CSW-TLS-001");
    expect(key.title).toBe("Leaf public key: ML-DSA-65");
    expect(key.pq_status).toBe("safe");
  });
});

describe("live probe: a runtime that does not report TLS 1.3 groups (Node 22)", () => {
  // Node 22 returns {} from getEphemeralKeyInfo() for every TLS 1.3 group, so
  // the probe could never confirm an ML-KEM group there. Simulated here.
  afterEach(() => vi.restoreAllMocks());
  const hideGroups = (): void => void vi.spyOn(TLSSocket.prototype, "getEphemeralKeyInfo").mockReturnValue({});

  it("attributes the group from the single-group TLS 1.3 offer, at high confidence", async (ctx) => {
    ctx.skip(!HAS_MLKEM, NO_MLKEM);
    hideGroups();
    const findings = await scanServer({ ...RSA, minVersion: "TLSv1.3", ecdhCurve: "X25519MLKEM768" });
    const kex = byId(findings, "CSW-TLS-005");
    expect(kex.title).toBe("Server supports hybrid post-quantum key exchange (X25519MLKEM768)");
    expect(kex.confidence).toBe("high");
    expect(kex.evidence).toMatch(/accepted=X25519MLKEM768 \(inferred from the single offered group/);
  });

  it("still never credits a TLS 1.2-only server", async () => {
    hideGroups();
    const findings = await scanServer({ ...RSA, maxVersion: "TLSv1.2", ciphers: "AES256-GCM-SHA384" });
    expect(byId(findings, "CSW-TLS-005").title).toMatch(/^RSA key exchange without forward secrecy/);
    expect(findings.some((f) => /supports .*post-quantum/.test(f.title))).toBe(false);
  });
});

describe("live probe: certificate chain", () => {
  it("flags a SHA-1 intermediate the server sent, and the failed validation", async () => {
    const chain = Buffer.concat([
      fixture("sha1-chain-leaf-cert.pem"),
      readFileSync(fileURLToPath(new URL("./fixtures/tls-certs/sha1-intermediate.pem", import.meta.url))),
    ]);
    // OpenSSL refuses to load a SHA-1-signed chain above security level 0.
    const findings = await scanServer({ key: fixture("sha1-chain-leaf-key.pem"), cert: chain, ciphers: "DEFAULT:@SECLEVEL=0" });
    const sig = byId(findings, "CSW-TLS-006");
    expect(sig.title).toBe("Intermediate signature algorithm: sha1WithRSAEncryption");
    expect(sig.severity).toBe("high");
    expect(byId(findings, "CSW-TLS-008").title).toMatch(/did not validate/);
  });
});

describe("live probe: target resolution", () => {
  it("refuses a hostname that resolves to loopback without --allow-private", async () => {
    const server = await startServer({ ...RSA });
    try {
      await expect(scanTls("localhost", { port: server.port, timeoutMs: 5000 })).rejects.toThrow(/non-public/);
      expect(server.connections()).toBe(0);
    } finally {
      await server.close();
    }
  });

  it("connects through the vetted addresses of a hostname when private targets are allowed", async () => {
    const server = await startServer({ ...RSA });
    try {
      const findings = await scanTls("localhost", { port: server.port, allowPrivate: true, timeoutMs: 5000 });
      expect(byId(findings, "CSW-TLS-001").title).toBe("Leaf public key: RSA-2048");
      // Connected by vetted IP, but the original name still went out as SNI.
      expect(server.servernames().length).toBeGreaterThan(0);
      expect(new Set(server.servernames())).toEqual(new Set(["localhost"]));
    } finally {
      await server.close();
    }
  });
});
