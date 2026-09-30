import { describe, expect, it } from "vitest";
import { scanContent } from "../src/scanners/source";

/**
 * MD5/SHA-1 severity by role. jshttp/etag used to come out as
 * `high | confirmed | act-now`, failing any `--fail-on high` gate, although an
 * ETag relies on no collision resistance and SP 800-131A permits SHA-1 outside
 * digital signatures.
 */
const ETAG = `
var crypto = require('crypto')

function entitytag (entity) {
  if (entity.length === 0) {
    return '"0-2jmj7l5rSw0yVb/vlWAYkK/YBwk"'
  }
  var hash = crypto
    .createHash('sha1')
    .update(entity, 'utf8')
    .digest('base64')
    .substring(0, 27)
  return '"' + entity.length.toString(16) + '-' + hash + '"'
}
`;

describe("weak-hash role from the surrounding code", () => {
  it("downgrades the jshttp/etag call: low severity, off the act-now board, with the reason", () => {
    const [hash] = scanContent("index.js", ETAG);
    expect(hash?.ruleId).toBe("source/node-crypto/weak-hash-non-security");
    expect(hash?.severity).toBe("low");
    expect(hash?.pq_status).toBe("unknown"); // the risk model files only `vulnerable` hashes as act-now
    expect(hash?.confidence).toBe("high");
    expect(hash?.recommendation).toMatch(/entitytag/);
    expect(hash?.recommendation).toMatch(/SP 800-131A/);
  });

  it("recognises an ETag header, a cache key and a git object id", () => {
    const code = [
      'import { createHash } from "node:crypto";',
      'res.setHeader("ETag", createHash("sha1").update(body).digest("hex"));',
      'const cacheKey = createHash("md5").update(url).digest("hex");',
      'function gitBlobId(buf) { return createHash("sha1").update(`blob ${buf.length}\\0`).update(buf).digest("hex"); }',
    ].join("\n");
    const hashes = scanContent("server.ts", code).filter((f) => f.algorithm === "SHA-1" || f.algorithm === "MD5");
    expect(hashes).toHaveLength(3);
    expect(hashes.every((f) => f.ruleId === "source/node-crypto/weak-hash-non-security" && f.severity === "low")).toBe(true);
  });

  it("keeps a security use high", () => {
    const code = [
      'const crypto = require("crypto");',
      'function hashPassword(pw) { return crypto.createHash("md5").update(pw).digest("hex"); }',
    ].join("\n");
    const [hash] = scanContent("auth.js", code);
    expect(hash?.ruleId).toBe("source/node-crypto/weak-hash");
    expect(hash?.severity).toBe("high");
    expect(hash?.pq_status).toBe("vulnerable");
    expect(hash?.recommendation).toMatch(/hashPassword/);
  });

  it("lets a security word win over a non-security one in the same context", () => {
    const code = 'const crypto = require("crypto");\nconst cachedToken = crypto.createHash("sha1").update(secret).digest("hex");';
    const [hash] = scanContent("a.js", code);
    expect(hash?.ruleId).toBe("source/node-crypto/weak-hash");
    expect(hash?.severity).toBe("high");
  });

  it("rates an unexplained use medium (not high) and says why", () => {
    const code = 'const crypto = require("crypto");\nconst h = crypto.createHash("sha1").update(data).digest("hex");';
    const [hash] = scanContent("a.js", code);
    expect(hash?.ruleId).toBe("source/node-crypto/weak-hash");
    expect(hash?.severity).toBe("medium");
    expect(hash?.recommendation).toMatch(/Nothing around this call/);
  });

  it("honours Python's usedforsecurity=False declaration", () => {
    const f = scanContent("a.py", "import hashlib\netag = hashlib.md5(body, usedforsecurity=False).hexdigest()\nh = hashlib.sha1(data)");
    expect(f[0]?.ruleId).toBe("source/python-hashlib/weak-hash-non-security");
    expect(f[0]?.severity).toBe("low");
    expect(f[1]?.ruleId).toBe("source/python-hashlib/weak-hash");
    expect(f[1]?.severity).toBe("medium");
  });
});
