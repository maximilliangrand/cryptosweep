/**
 * Weak-hash role beyond the call's own ancestors. The AST also reads where the
 * digest's variable goes next (the RFC 6455 WebSocket handshake in undici
 * compares it with `Sec-WebSocket-Accept`), and the regex languages read the
 * names on the match's line, so an ETag or cache key in Python, Go or the JVM
 * is no longer medium and act-now.
 */
import { describe, expect, it } from "vitest";
import { assessThreat } from "../src/model/risk";
import { scanContent } from "../src/scanners/source";
import { NON_SECURITY_VARIANT, SOURCE_RULES } from "../src/scanners/source-rules";

function weakHashes(path: string, code: string): ReturnType<typeof scanContent> {
  return scanContent(path, code).filter((f) => f.algorithm === "SHA-1" || f.algorithm === "MD5");
}

function expectNonSecurity(path: string, code: string, ruleId: string): void {
  const [hash, ...rest] = weakHashes(path, code);
  expect(rest).toEqual([]);
  expect(hash?.ruleId).toBe(ruleId);
  expect(hash?.severity).toBe("low");
  expect(hash?.pq_status).toBe("unknown");
  if (hash) expect(assessThreat(hash).threats).toEqual([]); // off the act-now board
}

/** undici lib/web/websocket/connection.js, the RFC 6455 Sec-WebSocket-Accept check. */
const UNDICI_WEBSOCKET = `
'use strict'
const crypto = require('node:crypto')
const { uid } = require('./constants')

function onResponse (response, keyValue, handler) {
  const secWSAccept = response.headersList.get('Sec-WebSocket-Accept')
  const digest = crypto.createHash('sha1').update(keyValue + uid).digest('base64')
  if (secWSAccept !== digest) {
    failWebsocketConnection(handler, 1002, 'Incorrect hash received in Sec-WebSocket-Accept header.')
    return
  }
}
`;

describe("JavaScript: where the digest goes", () => {
  it("rates undici's Sec-WebSocket-Accept SHA-1 as non-security", () => {
    expectNonSecurity("lib/web/websocket/connection.js", UNDICI_WEBSOCKET, "source/node-crypto/weak-hash-non-security");
    const [hash] = weakHashes("lib/web/websocket/connection.js", UNDICI_WEBSOCKET);
    expect(hash?.recommendation).toMatch(/secWSAccept/);
  });

  it("recognises the RFC 6455 GUID concatenated into the digest", () => {
    const code =
      'const crypto = require("crypto");\nconst accept = crypto.createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");\n';
    expectNonSecurity("ws.js", code, "source/node-crypto/weak-hash-non-security");
  });

  it("follows the variable into an ETag header", () => {
    const code = 'import { createHash } from "node:crypto";\nconst digest = createHash("md5").update(body).digest("hex");\nres.setHeader("ETag", digest);\n';
    expectNonSecurity("server.ts", code, "source/node-crypto/weak-hash-non-security");
  });

  it("lets a security use of the variable win", () => {
    const code =
      'import { createHash } from "node:crypto";\nconst digest = createHash("md5").update(pw).digest("hex");\nres.setHeader("ETag", digest);\nif (digest !== storedPassword) throw new Error("no");\n';
    const [hash] = weakHashes("auth.ts", code);
    expect(hash?.ruleId).toBe("source/node-crypto/weak-hash");
    expect(hash?.severity).toBe("high");
    expect(hash?.recommendation).toMatch(/storedPassword/);
  });
});

describe("regex languages: the names on the line", () => {
  it.each([
    ["etag = hashlib.md5(body).hexdigest()"],
    ["cache_key = hashlib.sha1(url.encode()).hexdigest()"],
    ['git_oid = hashlib.new("sha1", blob).hexdigest()'],
  ])("Python: %s is non-security", (line) => {
    expectNonSecurity("app/views.py", `import hashlib\n${line}\n`, "source/python-hashlib/weak-hash-non-security");
  });

  it("Python: a password hash is high, and an unexplained one stays medium", () => {
    const [password, plain] = weakHashes("app/auth.py", "import hashlib\npassword_hash = hashlib.md5(pw).hexdigest()\nh = hashlib.sha1(data)\n");
    expect(password?.ruleId).toBe("source/python-hashlib/weak-hash");
    expect(password?.severity).toBe("high");
    expect(password?.recommendation).toMatch(/password_hash/);
    expect(plain?.severity).toBe("medium");
  });

  it("PyCryptodome", () => {
    expectNonSecurity("app/cache.py", "from Crypto.Hash import SHA\ncache_key = SHA.new(data).hexdigest()\n", "source/pycryptodome/weak-hash-non-security");
  });

  it("Go", () => {
    expectNonSecurity("etag.go", 'import "crypto/md5"\netag := fmt.Sprintf("%x", md5.Sum(body))\n', "source/go/weak-hash-non-security");
  });

  it("Java", () => {
    expectNonSecurity(
      "src/ETags.java",
      'String etag = toHex(MessageDigest.getInstance("MD5").digest(body));\n',
      "source/java/weak-hash-non-security",
    );
  });

  it("the JavaScript regex fallback", () => {
    expectNonSecurity("src/broken.js", 'const etag = crypto.createHash("sha1").update(b).digest("hex");\n} broken', "source/node-crypto/weak-hash-non-security");
  });

  it("reads only the match's own line", () => {
    const code = "import hashlib\netag = compute()\nh = hashlib.sha1(data)\n";
    expect(weakHashes("a.py", code)[0]?.severity).toBe("medium");
  });
});

describe("every role-sensitive weak-hash rule", () => {
  it("has a non-security variant", () => {
    const sensitive = SOURCE_RULES.filter((rule) => rule.roleSensitive === true).map((rule) => rule.id);
    expect(sensitive.length).toBeGreaterThan(0);
    for (const id of sensitive) expect(NON_SECURITY_VARIANT[id], id).toBeDefined();
  });
});
