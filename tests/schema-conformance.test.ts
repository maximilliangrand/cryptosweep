/**
 * Validates generated CBOM and SARIF against the official schemas, vendored in
 * tests/fixtures/schemas/ (CycloneDX 1.6 bom + spdx + jsf, from
 * github.com/CycloneDX/specification tag 1.6.1; SARIF 2.1.0 errata01, from
 * github.com/oasis-tcs/sarif-spec).
 *
 * No JSON Schema validator is a dependency, so this file carries a compact one
 * for exactly the keywords those schemas use (draft-04 and draft-07). It throws
 * on any keyword it does not implement, so a schema update cannot silently
 * weaken the check.
 */
import { readFileSync } from "node:fs";
import { X509Certificate } from "node:crypto";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { buildReport } from "../src/report";
import type { Finding } from "../src/report";
import { toCbom } from "../src/output/cbom";
import { toSarif } from "../src/output/sarif";
import { scanContent } from "../src/scanners/source";
import { matchDeps } from "../src/scanners/deps";
import { analyzeTls, parseCertificate } from "../src/scanners/tls";
import type { CertInfo, TlsScanResult } from "../src/scanners/tls";

// ---------- compact JSON Schema validator ----------

type SchemaObject = Record<string, unknown>;
type Schema = boolean | SchemaObject;

const ANNOTATIONS = new Set([
  "$schema",
  "$id",
  "id",
  "$comment",
  "title",
  "description",
  "examples",
  "default",
  "deprecated",
  "meta:enum",
  "definitions",
]);

const ASSERTIONS = new Set([
  "$ref",
  "type",
  "enum",
  "const",
  "properties",
  "patternProperties",
  "additionalProperties",
  "required",
  "items",
  "additionalItems",
  "minItems",
  "maxItems",
  "uniqueItems",
  "minLength",
  "maxLength",
  "pattern",
  "minimum",
  "maximum",
  "format",
  "oneOf",
  "anyOf",
  "allOf",
  "not",
  "if",
  "then",
  "else",
]);

const isObject = (value: unknown): value is SchemaObject =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** Canonical JSON (sorted keys), for enum/const/uniqueItems equality. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (isObject(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

const DATE_TIME = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$/;
const URI_REFERENCE_CHARS = /^(?:[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})*$/;

function isUriReference(value: string, allowUnicode: boolean): boolean {
  let ascii = "";
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 0x21 || code === 0x7f || (code >= 0x80 && code <= 0x9f)) return false;
    ascii += code > 0x7f ? (allowUnicode ? "a" : " ") : char;
  }
  return URI_REFERENCE_CHARS.test(ascii);
}

const FORMATS: Record<string, (value: string) => boolean> = {
  "date-time": (v) => DATE_TIME.test(v) && !Number.isNaN(Date.parse(v)),
  uri: (v) => /^[A-Za-z][A-Za-z0-9+.-]*:/.test(v) && isUriReference(v, false),
  "uri-reference": (v) => isUriReference(v, false),
  "iri-reference": (v) => isUriReference(v, true),
  "idn-email": (v) => /^[^\s@]+@[^\s@]+$/.test(v),
};

function typeMatches(type: string, value: unknown): boolean {
  switch (type) {
    case "object":
      return isObject(value);
    case "array":
      return Array.isArray(value);
    case "string":
      return typeof value === "string";
    case "boolean":
      return typeof value === "boolean";
    case "null":
      return value === null;
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    case "integer":
      return Number.isInteger(value);
    default:
      throw new Error(`unsupported type ${type}`);
  }
}

class SchemaValidator {
  private readonly documents = new Map<string, SchemaObject>();
  private readonly patterns = new Map<string, RegExp>();

  constructor(schemas: SchemaObject[]) {
    for (const schema of schemas) {
      const id = String(schema.$id ?? schema.id ?? "");
      if (!id) throw new Error("schema without an id");
      this.documents.set(id.split("#")[0] ?? id, schema);
    }
  }

  validate(documentId: string, instance: unknown): string[] {
    const root = this.documents.get(documentId);
    if (!root) throw new Error(`unknown schema ${documentId}`);
    const errors: string[] = [];
    this.check(root, documentId, instance, "$", errors);
    return errors;
  }

  private resolve(ref: string, base: string): { schema: Schema; base: string } {
    const url = new URL(ref, base);
    const fragment = decodeURIComponent(url.hash.replace(/^#/, ""));
    url.hash = "";
    const documentId = url.toString();
    const document = this.documents.get(documentId);
    if (!document) throw new Error(`unresolvable $ref ${ref} from ${base}`);
    let node: unknown = document;
    for (const token of fragment.split("/").slice(1)) {
      const key = token.replace(/~1/g, "/").replace(/~0/g, "~");
      node = isObject(node) ? node[key] : undefined;
    }
    if (typeof node !== "boolean" && !isObject(node)) throw new Error(`dangling $ref ${ref}`);
    return { schema: node, base: documentId };
  }

  private regex(pattern: string): RegExp {
    let compiled = this.patterns.get(pattern);
    if (!compiled) {
      try {
        compiled = new RegExp(pattern, "u");
      } catch {
        compiled = new RegExp(pattern);
      }
      this.patterns.set(pattern, compiled);
    }
    return compiled;
  }

  private passes(schema: Schema, base: string, value: unknown, path: string): boolean {
    const errors: string[] = [];
    this.check(schema, base, value, path, errors);
    return errors.length === 0;
  }

  private check(schema: Schema, base: string, value: unknown, path: string, errors: string[]): void {
    if (schema === true) return;
    if (schema === false) {
      errors.push(`${path}: not allowed`);
      return;
    }
    for (const keyword of Object.keys(schema)) {
      if (!ANNOTATIONS.has(keyword) && !ASSERTIONS.has(keyword)) throw new Error(`unsupported keyword ${keyword} at ${path}`);
    }
    if (typeof schema.$ref === "string") {
      // draft-04 / draft-07: siblings of $ref are ignored.
      const target = this.resolve(schema.$ref, base);
      this.check(target.schema, target.base, value, path, errors);
      return;
    }

    if (schema.type !== undefined) {
      const types = Array.isArray(schema.type) ? schema.type.map(String) : [String(schema.type)];
      if (!types.some((t) => typeMatches(t, value))) {
        errors.push(`${path}: expected ${types.join("|")}`);
        return;
      }
    }
    if (Array.isArray(schema.enum) && !schema.enum.some((option) => canonical(option) === canonical(value))) {
      errors.push(`${path}: ${JSON.stringify(value)} not in enum`);
    }
    if ("const" in schema && canonical(schema.const) !== canonical(value)) {
      errors.push(`${path}: expected const ${JSON.stringify(schema.const)}`);
    }

    if (typeof value === "string") this.checkString(schema, value, path, errors);
    if (typeof value === "number") {
      if (typeof schema.minimum === "number" && value < schema.minimum) errors.push(`${path}: below minimum ${schema.minimum}`);
      if (typeof schema.maximum === "number" && value > schema.maximum) errors.push(`${path}: above maximum ${schema.maximum}`);
    }
    if (Array.isArray(value)) this.checkArray(schema, base, value, path, errors);
    if (isObject(value)) this.checkObject(schema, base, value, path, errors);

    if (Array.isArray(schema.allOf)) {
      for (const sub of schema.allOf as Schema[]) this.check(sub, base, value, path, errors);
    }
    if (Array.isArray(schema.anyOf) && !(schema.anyOf as Schema[]).some((sub) => this.passes(sub, base, value, path))) {
      errors.push(`${path}: matches none of anyOf`);
    }
    if (Array.isArray(schema.oneOf)) {
      const matches = (schema.oneOf as Schema[]).filter((sub) => this.passes(sub, base, value, path)).length;
      if (matches !== 1) errors.push(`${path}: matches ${matches} of oneOf (expected exactly 1)`);
    }
    if (schema.not !== undefined && this.passes(schema.not as Schema, base, value, path)) {
      errors.push(`${path}: matches a "not" schema`);
    }
    if (schema.if !== undefined) {
      const branch = this.passes(schema.if as Schema, base, value, path) ? schema.then : schema.else;
      if (branch !== undefined) this.check(branch as Schema, base, value, path, errors);
    }
  }

  private checkString(schema: SchemaObject, value: string, path: string, errors: string[]): void {
    const length = [...value].length;
    if (typeof schema.minLength === "number" && length < schema.minLength) errors.push(`${path}: shorter than ${schema.minLength}`);
    if (typeof schema.maxLength === "number" && length > schema.maxLength) errors.push(`${path}: longer than ${schema.maxLength}`);
    if (typeof schema.pattern === "string" && !this.regex(schema.pattern).test(value)) {
      errors.push(`${path}: does not match ${schema.pattern}`);
    }
    if (typeof schema.format === "string") {
      const check = FORMATS[schema.format];
      if (!check) throw new Error(`unsupported format ${schema.format}`);
      if (!check(value)) errors.push(`${path}: not a valid ${schema.format}: ${JSON.stringify(value)}`);
    }
  }

  private checkArray(schema: SchemaObject, base: string, value: unknown[], path: string, errors: string[]): void {
    if (typeof schema.minItems === "number" && value.length < schema.minItems) errors.push(`${path}: fewer than ${schema.minItems} items`);
    if (typeof schema.maxItems === "number" && value.length > schema.maxItems) errors.push(`${path}: more than ${schema.maxItems} items`);
    if (schema.uniqueItems === true && new Set(value.map(canonical)).size !== value.length) errors.push(`${path}: items not unique`);
    if (Array.isArray(schema.items)) {
      const tuple = schema.items as Schema[];
      value.forEach((item, i) => {
        const sub = tuple[i] ?? (schema.additionalItems as Schema | undefined);
        if (sub !== undefined) this.check(sub, base, item, `${path}[${i}]`, errors);
      });
    } else if (schema.items !== undefined) {
      value.forEach((item, i) => this.check(schema.items as Schema, base, item, `${path}[${i}]`, errors));
    }
  }

  private checkObject(schema: SchemaObject, base: string, value: SchemaObject, path: string, errors: string[]): void {
    for (const key of Array.isArray(schema.required) ? (schema.required as string[]) : []) {
      if (!(key in value)) errors.push(`${path}: missing required ${key}`);
    }
    const properties = isObject(schema.properties) ? schema.properties : {};
    const patternProperties = isObject(schema.patternProperties) ? schema.patternProperties : {};
    for (const [key, child] of Object.entries(value)) {
      const childPath = `${path}.${key}`;
      let matched = false;
      if (key in properties) {
        matched = true;
        this.check(properties[key] as Schema, base, child, childPath, errors);
      }
      for (const [pattern, sub] of Object.entries(patternProperties)) {
        if (this.regex(pattern).test(key)) {
          matched = true;
          this.check(sub as Schema, base, child, childPath, errors);
        }
      }
      if (!matched && schema.additionalProperties !== undefined) {
        this.check(schema.additionalProperties as Schema, base, child, childPath, errors);
      }
    }
  }
}

// ---------- vendored schemas ----------

const SCHEMAS = fileURLToPath(new URL("./fixtures/schemas/", import.meta.url));
const loadSchema = (name: string): SchemaObject => JSON.parse(readFileSync(`${SCHEMAS}${name}`, "utf8")) as SchemaObject;

const BOM_ID = "http://cyclonedx.org/schema/bom-1.6.schema.json";
const SARIF_ID = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

const validator = new SchemaValidator([
  loadSchema("bom-1.6.schema.json"),
  loadSchema("spdx.schema.json"),
  loadSchema("jsf-0.82.schema.json"),
  loadSchema("sarif-schema-2.1.0.json"),
]);

// ---------- real scanner output ----------

const AT = new Date("2026-10-01T00:00:00.000Z");
const CERTS = fileURLToPath(new URL("./fixtures/certs/", import.meta.url));

function cert(name: string): CertInfo {
  const parsed = parseCertificate(new X509Certificate(readFileSync(`${CERTS}${name}`)).raw, true);
  if (!parsed) throw new Error(`fixture ${name} did not parse`);
  return parsed;
}

const SOURCE = [
  'import crypto from "node:crypto";',
  'import jwt from "jsonwebtoken";',
  'crypto.createHash("md5"); crypto.createHash("sha1");',
  'crypto.createCipheriv("des-ede3-cbc", k, iv); crypto.createCipheriv("rc4", k, iv);',
  'jwt.sign(p, k, { algorithm: "RS256" }); jwt.verify(t, k, { algorithms: ["HS256", "ES256", "none"] });',
  "const key = `-----BEGIN RSA PRIVATE KEY-----",
  "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun",
  "-----END RSA PRIVATE KEY-----`;",
  "const pub = `-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqh\n-----END PUBLIC KEY-----`;",
].join("\n");

function tlsFindings(name: string, result: Partial<TlsScanResult>, host = "example.com"): Finding[] {
  const scan: TlsScanResult = {
    protocol: "TLSv1.3",
    cipherName: "TLS_AES_256_GCM_SHA384",
    groupName: null,
    hybridKex: "unsupported",
    chain: [cert(name)],
    ...result,
  };
  return analyzeTls(scan, `${host}:443`, AT, { host, port: 443 });
}

const TLS_CERTS = fileURLToPath(new URL("./fixtures/tls-certs/", import.meta.url));

/** An RSASSA-PSS leaf, served over TLS 1.2 static-RSA key transport, and a DHE-1024 server: every new primitive kind. */
function keyTransportFindings(): Finding[] {
  const pss = parseCertificate(new X509Certificate(readFileSync(`${TLS_CERTS}pss-sha256.pem`)).raw, true);
  if (!pss) throw new Error("fixture pss-sha256.pem did not parse");
  return [
    ...analyzeTls({ protocol: "TLSv1.2", cipherName: "AES256-GCM-SHA384", groupName: null, chain: [pss] }, "pss.example:443", AT, { host: "pss.example", port: 443 }),
    ...analyzeTls(
      { protocol: "TLSv1.2", cipherName: "DHE-RSA-AES128-GCM-SHA256", groupName: null, groupBits: 1024, chain: [cert("rsa2048.pem")] },
      "dhe.example:443",
      AT,
      { host: "dhe.example", port: 443 },
    ),
    ...scanContent("src/kdf.js", 'const c = require("crypto");\nc.pbkdf2Sync(p, s, 1, 32, "sha1");\nc.createHmac("md5", k);\nc.generateKeyPairSync("ec");'),
  ];
}

/** Everything the scanners emit today, plus the structured fields they can attach. */
function corpus(): Finding[] {
  const leaf = cert("rsa2048.pem");
  return [
    ...scanContent("src/app.ts", SOURCE),
    ...keyTransportFindings(),
    ...scanContent("docs/My Notes #1.md", 'crypto.createHash("md5")'),
    ...scanContent("src/ünïcode dir/[x](https:evil).js", 'require("crypto").createHash("sha1")'),
    ...matchDeps([
      { name: "tweetnacl", version: "1.0.3", ecosystem: "npm", manifestPath: "package.json" },
      { name: "jsonwebtoken", version: "^9.0.2", ecosystem: "npm", manifestPath: "package.json" },
      { name: "rustls", version: "0.23.27", ecosystem: "cargo", manifestPath: "crates/net/Cargo.toml" },
      { name: "pynacl", version: "==1.5.0", ecosystem: "python", manifestPath: "requirements.txt" },
      { name: "liboqs-python", version: "0.16.0.1", ecosystem: "python", manifestPath: "requirements.txt" },
    ]),
    ...tlsFindings("rsa-md5.pem", { hybridKex: "unsupported" }),
    ...tlsFindings("rsa-sha1.pem", { hybridKex: "supported", protocol: "TLSv1.2" }, "sha1.example.com"),
    ...tlsFindings("ec-p256.pem", { hybridKex: "unknown", protocol: "TLSv1" }, "2001:db8::1"),
    ...tlsFindings("ed25519.pem", { hybridKex: undefined, groupName: "X25519" }, "ed.example.com"),
    {
      id: "CSW-TLS-900",
      ruleId: "tls/leaf-signature",
      severity: "medium",
      category: "tls",
      title: `Leaf signature algorithm: ${leaf.signatureAlgorithm}`,
      evidence: "structured.example.com:443",
      location: { host: "structured.example.com", port: 443 },
      pq_status: "vulnerable",
      confidence: "confirmed",
      algorithm: leaf.signatureAlgorithm,
      oid: leaf.signatureOid ?? undefined,
      recommendation: "Plan ML-DSA certificates.",
      certificates: [
        {
          subject: leaf.subject,
          issuer: leaf.issuer,
          notValidBefore: leaf.validFrom,
          notValidAfter: leaf.validTo,
          signatureAlgorithm: leaf.signatureAlgorithm,
          signatureOid: leaf.signatureOid ?? undefined,
          publicKey: `RSA-${leaf.keyBits ?? 0}`,
          publicKeyBits: leaf.keyBits ?? undefined,
        },
      ],
      protocol: { type: "tls", version: "1.3", cipherSuite: "TLS_AES_128_GCM_SHA256", group: "X25519MLKEM768" },
    },
    {
      id: "CSW-SRC-900",
      ruleId: "source/pqc",
      severity: "info",
      category: "source",
      title: "Post-quantum primitives in use",
      evidence: "/abs/path/main.go:3",
      location: { path: "/abs/path/main.go", line: 3 },
      pq_status: "safe",
      algorithm: "ML-KEM-1024",
      recommendation: "Keep.",
    },
    {
      id: "CSW-SRC-901",
      severity: "info",
      category: "source",
      title: "Signature",
      evidence: "C:\\repo\\sign.py:1",
      location: { path: "C:\\repo\\sign.py", line: 1 },
      pq_status: "safe",
      algorithm: "SLH-DSA-SHAKE-192f",
      recommendation: "Keep.",
    },
  ];
}

// ---------- tests ----------

describe("compact schema validator", () => {
  it("rejects documents the official schemas reject", () => {
    const cbom = JSON.parse(toCbom(buildReport("example.com", corpus(), AT))) as {
      components: Array<{ cryptoProperties?: { algorithmProperties?: Record<string, unknown> } } & Record<string, unknown>>;
    };
    const algorithm = cbom.components.find((c) => c.cryptoProperties?.algorithmProperties);
    expect(algorithm).toBeDefined();
    const props = algorithm?.cryptoProperties?.algorithmProperties ?? {};

    props.primitive = "rc4-cipher";
    expect(validator.validate(BOM_ID, cbom).join("\n")).toMatch(/not in enum/);
    props.primitive = "stream-cipher";
    props.nistQuantumSecurityLevel = 7;
    expect(validator.validate(BOM_ID, cbom).join("\n")).toMatch(/above maximum 6/);
    props.nistQuantumSecurityLevel = 0;
    props.invented = true;
    expect(validator.validate(BOM_ID, cbom).join("\n")).toMatch(/invented: not allowed/);
    delete props.invented;
    expect(validator.validate(BOM_ID, cbom)).toEqual([]);

    const sarif = JSON.parse(toSarif(buildReport("example.com", corpus(), AT))) as {
      runs: Array<{ tool: { driver: Record<string, unknown> }; results: Array<Record<string, unknown>> }>;
    };
    const run = sarif.runs[0];
    if (!run?.results[0]) throw new Error("no SARIF results");
    run.results[0].level = "fatal";
    expect(validator.validate(SARIF_ID, sarif).join("\n")).toMatch(/level: "fatal" not in enum/);
    run.results[0].level = "error";
    delete run.tool.driver.name;
    expect(validator.validate(SARIF_ID, sarif).join("\n")).toMatch(/missing required name/);
  });

  it("follows $ref across documents (into the vendored SPDX list)", () => {
    const withLicense = (id: string): unknown => ({
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      components: [{ type: "library", name: "x", licenses: [{ license: { id } }] }],
    });
    expect(validator.validate(BOM_ID, withLicense("MIT"))).toEqual([]);
    expect(validator.validate(BOM_ID, withLicense("NOT-A-LICENSE")).length).toBeGreaterThan(0);
  });

  it("refuses schemas that use keywords it does not implement", () => {
    const strict = new SchemaValidator([{ $id: "urn:test", type: "object", propertyNames: { pattern: "^a" } }]);
    expect(() => strict.validate("urn:test", {})).toThrow(/unsupported keyword propertyNames/);
  });
});

describe("CycloneDX 1.6 conformance", () => {
  it("validates the CBOM for real scanner output against bom-1.6.schema.json", () => {
    const cbom = JSON.parse(toCbom(buildReport("./fixture repo", corpus(), AT))) as unknown;
    expect(validator.validate(BOM_ID, cbom)).toEqual([]);
  });

  it("validates an empty CBOM", () => {
    const cbom = JSON.parse(toCbom(buildReport("clean.example.com", [], AT))) as unknown;
    expect(validator.validate(BOM_ID, cbom)).toEqual([]);
  });

  it("keeps every bom-ref unique and every reference resolvable", () => {
    const cbom = JSON.parse(toCbom(buildReport("example.com", corpus(), AT))) as {
      metadata: { component: { "bom-ref": string } };
      components: Array<Record<string, unknown> & { "bom-ref": string }>;
      dependencies?: Array<{ ref: string; dependsOn?: string[]; provides?: string[] }>;
    };
    const refs = cbom.components.map((c) => c["bom-ref"]);
    expect(new Set(refs).size).toBe(refs.length);
    const known = new Set([...refs, cbom.metadata.component["bom-ref"]]);

    const referenced: string[] = [];
    for (const dep of cbom.dependencies ?? []) referenced.push(dep.ref, ...(dep.dependsOn ?? []), ...(dep.provides ?? []));
    const collect = (value: unknown): void => {
      if (Array.isArray(value)) value.forEach(collect);
      else if (value && typeof value === "object") {
        for (const [key, child] of Object.entries(value)) {
          if (/Ref$/.test(key) && typeof child === "string") referenced.push(child);
          else if (key === "cryptoRefArray" && Array.isArray(child)) referenced.push(...child.map(String));
          else collect(child);
        }
      }
    };
    collect(cbom.components);
    expect(referenced.length).toBeGreaterThan(0);
    expect(referenced.filter((r) => !known.has(r))).toEqual([]);
  });
});

describe("SARIF 2.1.0 conformance", () => {
  it("validates the SARIF log for real scanner output against sarif-schema-2.1.0.json", () => {
    const sarif = JSON.parse(toSarif(buildReport("./fixture repo", corpus(), AT))) as unknown;
    expect(validator.validate(SARIF_ID, sarif)).toEqual([]);
  });

  it("validates an empty SARIF log", () => {
    const sarif = JSON.parse(toSarif(buildReport("clean.example.com", [], AT))) as unknown;
    expect(validator.validate(SARIF_ID, sarif)).toEqual([]);
  });

  it("points every result's ruleIndex at the rule with its ruleId", () => {
    const sarif = JSON.parse(toSarif(buildReport("example.com", corpus(), AT))) as {
      runs: Array<{ tool: { driver: { rules: Array<{ id: string }> } }; results: Array<{ ruleId: string; ruleIndex: number }> }>;
    };
    const run = sarif.runs[0];
    expect(run?.results.length).toBeGreaterThan(0);
    for (const result of run?.results ?? []) expect(run?.tool.driver.rules[result.ruleIndex]?.id).toBe(result.ruleId);
  });
});
