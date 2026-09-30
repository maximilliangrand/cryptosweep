import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
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

function site(path: string, line: number, rule: string, alg: string, confidence: Finding["confidence"] = "confirmed"): Finding {
  return finding({
    id: `CSW-JWT-${line}`,
    ruleId: `jwt/jsonwebtoken/${rule}`,
    category: "jwt",
    severity: rule === "hmac" ? "low" : "high",
    pq_status: rule === "hmac" ? "safe" : "vulnerable",
    confidence,
    algorithm: `JWT-${alg}`,
    evidence: `${path}:${line}`,
    location: { path, line },
  });
}

function dep(manifest: string, name = "jsonwebtoken", ecosystem = "npm"): Finding {
  return finding({
    id: `CSW-DEP-${manifest}`,
    ruleId: `deps/${ecosystem}-${name}`,
    confidence: "medium",
    evidence: `${manifest}:${name}@9.0.2`,
    location: { path: manifest },
  });
}

const HS256 = site("auth.js", 2, "hmac", "HS256");

describe("reconcile", () => {
  it("downgrades a direct dependency whose call sites all pin HMAC, citing them", () => {
    const [, out] = reconcile([HS256, dep("package.json")]);
    expect(out?.severity).toBe("low");
    expect(out?.pq_status).toBe("transitional");
    expect(out?.recommendation).toMatch(/HMAC \(symmetric\)/);
    expect(out?.recommendation).toContain("HS256 at auth.js:2");
  });

  it("leaves the verdict alone when an asymmetric algorithm is also used", () => {
    const [, , out] = reconcile([HS256, site("sign.js", 4, "rsa", "RS256"), dep("package.json")]);
    expect(out?.severity).toBe("high");
  });

  it("does not downgrade on regex-tier evidence alone", () => {
    const [, out] = reconcile([site("auth.js", 2, "hmac", "HS256", "medium"), dep("package.json")]);
    expect(out?.severity).toBe("high");
  });

  it("is blocked by an asymmetric algorithm even at lower confidence", () => {
    // The old rule only looked at confirmed findings, so a medium RS256 in the same report was ignored.
    const [, , out] = reconcile([HS256, site("legacy.js", 9, "rsa", "RS256", "medium"), dep("package.json")]);
    expect(out?.severity).toBe("high");
  });

  it("is blocked by a call site whose algorithm is chosen at runtime", () => {
    const [, , out] = reconcile([HS256, site("sign.js", 3, "algorithm-unresolved", "unknown", "confirmed"), dep("package.json")]);
    expect(out?.severity).toBe("high");
  });

  it("scopes evidence to the package that declares the library", () => {
    // Old rule: one confirmed HS256 anywhere downgraded every JWT library repo-wide,
    // including a package with no call-site evidence at all.
    const findings = [
      site("packages/a/auth.js", 2, "hmac", "HS256"),
      dep("packages/a/package.json"),
      dep("packages/b/package.json"),
    ];
    const out = reconcile(findings);
    expect(out[1]?.severity).toBe("low");
    expect(out[2]?.severity).toBe("high");
  });

  it("does not let a nested package's call sites justify its parent", () => {
    const out = reconcile([site("apps/web/auth.js", 2, "hmac", "HS256"), dep("package.json"), dep("apps/web/package.json")]);
    expect(out[1]?.severity).toBe("high"); // root: no call sites of its own
    expect(out[2]?.severity).toBe("low");
  });

  it("never touches lockfile entries, non-JWT toolkits, or Python and Rust libraries", () => {
    const out = reconcile([
      HS256,
      dep("pnpm-lock.yaml"),
      dep("package.json", "jsrsasign"),
      dep("requirements.txt", "pyjwt", "python"),
      dep("Cargo.toml", "rustls", "cargo"),
    ]);
    expect(out.slice(1).every((f) => f.severity === "high")).toBe(true);
  });

  it("does not reconcile against incomplete source evidence", () => {
    const gap = finding({ id: "CSW-COV-001", ruleId: "source/ast-fallback", category: "source", severity: "info", pq_status: "unknown" });
    const [, , out] = reconcile([HS256, gap, dep("package.json")]);
    expect(out?.severity).toBe("high");
  });
});

describe("scanLocalDir (end to end)", () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "csw-reconcile-"));
    // A package that only ever signs with HS256.
    await mkdir(join(dir, "svc"), { recursive: true });
    await writeFile(join(dir, "svc", "package.json"), JSON.stringify({ dependencies: { jsonwebtoken: "9.0.2" } }), "utf8");
    await writeFile(join(dir, "svc", "auth.js"), 'const jwt = require("jsonwebtoken");\njwt.sign(payload, secret, { algorithm: "HS256" });\n', "utf8");
    // The audit's fx5: an HS256 site next to a runtime-chosen algorithm, jsrsasign, and a Python RS256 service.
    await mkdir(join(dir, "web"), { recursive: true });
    await mkdir(join(dir, "api"), { recursive: true });
    await writeFile(join(dir, "web", "package.json"), JSON.stringify({ dependencies: { jsonwebtoken: "9.0.2", jsrsasign: "11.0.0" } }), "utf8");
    await writeFile(join(dir, "web", "auth.js"), 'const jwt = require("jsonwebtoken");\njwt.sign(p, k, { algorithm: "HS256" });\n', "utf8");
    await writeFile(join(dir, "web", "sign.js"), 'const jwt = require("jsonwebtoken");\njwt.sign(p, k, { algorithm: process.env.JWT_ALG });\n', "utf8");
    await writeFile(join(dir, "api", "requirements.txt"), "PyJWT==2.8.0\n", "utf8");
    await writeFile(join(dir, "api", "app.py"), 'import jwt\ntoken = jwt.encode(payload, key, algorithm="RS256")\n', "utf8");
  });
  afterAll(async () => rm(dir, { recursive: true, force: true }));

  it("downgrades only the package whose every call site is HMAC", async () => {
    const findings = await scanLocalDir(dir);
    const depAt = (manifest: string, name: string) =>
      findings.find((f) => f.category === "deps" && f.evidence.startsWith(`${manifest}:${name}@`));
    expect(depAt("svc/package.json", "jsonwebtoken")?.severity).toBe("low");
    expect(depAt("svc/package.json", "jsonwebtoken")?.recommendation).toContain("svc/auth.js:2");
    // The old rule turned all three into 'low transitional' with a false "every JWT algorithm is HMAC".
    expect(depAt("web/package.json", "jsonwebtoken")?.severity).toBe("high");
    expect(depAt("web/package.json", "jsrsasign")?.severity).toBe("medium");
    expect(depAt("api/requirements.txt", "pyjwt")?.pq_status).toBe("vulnerable");
    expect(findings.find((f) => f.ruleId === "jwt/pyjwt/rsa")?.evidence).toBe("api/app.py:2");
  });
});
