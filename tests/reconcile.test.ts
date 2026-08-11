import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { reconcile } from "../src/reconcile";
import { scanLocalDir } from "../src/orchestrate";
import type { Finding } from "../src/report";

function finding(over: Partial<Finding>): Finding {
  return {
    id: "F1",
    severity: "high",
    category: "deps",
    title: "t",
    evidence: "e",
    pq_status: "vulnerable",
    recommendation: "r",
    ...over,
  };
}

const HS256_CONFIRMED = finding({
  id: "CSW-JWT-001",
  category: "jwt",
  severity: "low",
  pq_status: "transitional",
  confidence: "confirmed",
  algorithm: "JWT-HS256",
});

const JSONWEBTOKEN = finding({
  id: "CSW-DEP-001",
  ruleId: "deps/npm-jsonwebtoken",
  confidence: "medium",
});

describe("reconcile", () => {
  it("downgrades a JWT library the source scanner proved is only used symmetrically", () => {
    const [, dep] = reconcile([HS256_CONFIRMED, JSONWEBTOKEN]);
    expect(dep?.severity).toBe("low");
    expect(dep?.pq_status).toBe("transitional");
    expect(dep?.recommendation).toMatch(/HMAC \(symmetric\)/);
  });

  it("leaves the registry verdict alone when an asymmetric algorithm is also confirmed", () => {
    const rs256 = finding({ id: "CSW-JWT-002", category: "jwt", confidence: "confirmed", algorithm: "JWT-RS256" });
    const [, , dep] = reconcile([HS256_CONFIRMED, rs256, JSONWEBTOKEN]);
    expect(dep?.severity).toBe("high");
    expect(dep?.pq_status).toBe("vulnerable");
  });

  it("does not act on unconfirmed (regex-tier) source evidence", () => {
    const guessed = { ...HS256_CONFIRMED, confidence: "medium" as const };
    const [, dep] = reconcile([guessed, JSONWEBTOKEN]);
    expect(dep?.severity).toBe("high");
  });

  it("never touches a library whose concern the JWT evidence does not settle", () => {
    const rustls = finding({ id: "CSW-DEP-002", ruleId: "deps/cargo-rustls" });
    const [, dep] = reconcile([HS256_CONFIRMED, rustls]);
    expect(dep?.severity).toBe("high");
  });
});

describe("scanLocalDir (end to end)", () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "csw-reconcile-"));
    await writeFile(join(dir, "package.json"), JSON.stringify({ dependencies: { jsonwebtoken: "9.0.2" } }), "utf8");
    await writeFile(
      join(dir, "auth.js"),
      'const jwt = require("jsonwebtoken");\njwt.sign(payload, secret, { algorithm: "HS256" });\n',
      "utf8",
    );
  });
  afterAll(async () => rm(dir, { recursive: true, force: true }));

  it("stops emitting two contradictory verdicts about the same library", async () => {
    const findings = await scanLocalDir(dir);
    const dep = findings.find((f) => f.ruleId === "deps/npm-jsonwebtoken");
    const jwt = findings.find((f) => f.category === "jwt");
    expect(jwt?.confidence).toBe("confirmed");
    expect(jwt?.algorithm).toBe("JWT-HS256");
    // The report used to carry `high | vulnerable` for jsonwebtoken alongside a
    // higher-confidence finding that the only algorithm in use is HMAC.
    expect(dep?.severity).toBe("low");
    expect(dep?.pq_status).toBe("transitional");
  });
});
