/**
 * The regex fallback (JS/TS over the AST size limit or unparseable, and other
 * text files) used to report every quoted "none" as a critical unsigned JWT as
 * soon as `jsonwebtoken` appeared anywhere in the file: a 1.14 MB bundle with
 * `display="none"` gave 500 critical findings and failed `--fail-on critical`.
 */
import { describe, expect, it } from "vitest";
import { scanContent } from "../src/scanners/source";

function algNone(path: string, content: string): ReturnType<typeof scanContent> {
  return scanContent(path, content).filter((f) => f.ruleId === "jwt/jsonwebtoken/alg-none");
}

describe("JWT alg none in the regex fallback", () => {
  it("does not read display=\"none\" in an oversized bundle as an unsigned JWT", () => {
    const filler = 'function f(e){e.style.display="none";return e}\n'.repeat(24_000);
    const bundle = `var jwt=require("jsonwebtoken");\n${filler}`;
    expect(bundle.length).toBeGreaterThan(1_000_000); // past the AST limit: the regex sweep runs
    expect(algNone("public/vendor.bundle.js", bundle)).toEqual([]);
  });

  it("does not read UI strings in an unparseable (Flow) file as an unsigned JWT", () => {
    const flow = '// @flow\nimport jwt from "jsonwebtoken";\ntype Props = {| mode: "none" |};\nconst css = { display: "none" };\n';
    expect(algNone("src/component.js", flow)).toEqual([]);
  });

  it("does not flag the comparison libraries use to reject alg none", () => {
    const code = 'const jwt = require("jsonwebtoken");\nif (header.alg === "none") throw new Error("unsigned");\n} broken';
    expect(algNone("src/check.js", code)).toEqual([]);
  });

  it.each([
    ['jwt.verify(token, key, { algorithms: ["none"] })', "an algorithms allow-list"],
    ['jwt.verify(token, key, { algorithms: ["HS256", "none"] })', "a list that also names none"],
    ["jwt.sign(payload, key, { algorithm: 'none' })", "a sign option"],
    ['const header = { "alg": "none" }; jwt.decode(t)', "a JSON header"],
    ['header.alg = "none"; jwt.sign(p, k)', "an assignment"],
  ])("still finds %s (%s)", (snippet) => {
    // A trailing syntax error forces the regex fallback.
    const findings = algNone("src/legacy.js", `const jwt = require("jsonwebtoken");\n${snippet}\n} broken`);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("critical");
    expect(findings[0]?.confidence).toBe("medium");
  });
});
