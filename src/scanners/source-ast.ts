/**
 * AST-based source scanner for JavaScript and TypeScript.
 *
 * Structural parsing (via @babel/parser, a devDependency inlined into the bundle
 * at build time) so weak-crypto matches come from the code's actual syntax tree,
 * not substrings: `createHash("md5")` in a comment or an unrelated string no
 * longer fires, and a call whose callee resolves to an imported `node:crypto` /
 * `jsonwebtoken` binding is reported at `confirmed` confidence. The regex sweep
 * in source.ts stays the fallback for non-JS/TS files, files that do not parse
 * cleanly, and (always) PEM key blocks.
 */
import { parse } from "@babel/parser";
import type {
  CallExpression,
  ImportDeclaration,
  Node,
  ObjectExpression,
  Program,
  VariableDeclarator,
} from "@babel/types";
import { REFS } from "../crypto";
import type { Category, Confidence, PqStatus, Reference, Severity } from "../report";

const JS_TS_EXT = /\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)$/i;
const MAX_PARSE_BYTES = 1_000_000;

const WEAK_HASH_ALG = /^(?:md5|sha-?1)$/i;
const WEAK_CIPHER_ALG = /(?:des|rc4|rc2)/i;
const HASH_METHODS = new Set(["createHash"]);
const CIPHER_METHODS = new Set([
  "createCipheriv",
  "createDecipheriv",
  "createCipher",
  "createDecipher",
]);
const JWT_METHODS = new Set(["sign", "verify", "decode"]);
const RECOGNIZED_JWT_ALGS = new Set([
  "HS256", "HS384", "HS512",
  "RS256", "RS384", "RS512",
  "ES256", "ES384", "ES512",
  "PS256", "PS384", "PS512",
  "EdDSA", "none",
]);

export function isJsTsFile(relPath: string): boolean {
  return JS_TS_EXT.test(relPath);
}

/** Post-quantum assessment of a JWT algorithm. Shared by the AST and regex paths. */
export function jwtAssessment(alg: string): { severity: Severity; pq: PqStatus; note: string } {
  if (alg === "none") {
    return {
      severity: "critical",
      pq: "vulnerable",
      note: 'JWT "alg: none" disables signature verification, remove it.',
    };
  }
  if (alg.startsWith("HS")) {
    return {
      severity: "low",
      pq: "transitional",
      note: "HMAC JWT is symmetric and quantum-resistant if the key is ≥256-bit; rotate and protect the secret.",
    };
  }
  return {
    severity: "high",
    pq: "vulnerable",
    note: `${alg} relies on RSA/ECDSA signatures broken by Shor's algorithm; plan a PQ-signature migration.`,
  };
}

/** The finding sink implemented by source.ts; the AST scanner emits through it. */
export type PushFinding = (
  prefix: string,
  baseSeverity: Severity,
  category: Category,
  title: string,
  index: number,
  pq: PqStatus,
  recommendation: string,
  opts?: { tier?: Confidence; algorithm?: string; references?: Reference[] },
) => void;

export interface ScanJsResult {
  used: "ast" | "fallback";
  /** [start,end) offsets of every string/template literal, for in-literal key upgrades. */
  stringRanges: Array<[number, number]>;
}

interface Bindings {
  cryptoNs: Set<string>;
  cryptoDirect: Map<string, string>;
  jwtNs: Set<string>;
  jwtDirect: Map<string, string>;
}

interface Hit {
  index: number;
  emit: () => void;
}

type Plugin = "typescript" | "jsx" | "decorators-legacy";

function pluginsFor(relPath: string): Plugin[] {
  const p = relPath.toLowerCase();
  if (/\.(?:ts|mts|cts)$/.test(p)) return ["typescript", "decorators-legacy"];
  if (/\.tsx$/.test(p)) return ["typescript", "jsx", "decorators-legacy"];
  return ["jsx"];
}

function isNode(value: unknown): value is Node {
  return typeof value === "object" && value !== null && typeof (value as { type?: unknown }).type === "string";
}

const SKIP_KEYS = new Set(["loc", "start", "end", "range", "leadingComments", "trailingComments", "innerComments"]);

/** Generic depth-first walk over real child nodes, ignoring position/comment metadata. */
function walk(node: Node, visit: (n: Node) => void): void {
  visit(node);
  for (const key of Object.keys(node)) {
    if (SKIP_KEYS.has(key)) continue;
    const value = (node as unknown as Record<string, unknown>)[key];
    if (Array.isArray(value)) {
      for (const child of value) if (isNode(child)) walk(child, visit);
    } else if (isNode(value)) {
      walk(value, visit);
    }
  }
}

/** The cooked value of a static string, or null for anything non-constant. */
function staticString(node: Node | null | undefined): string | null {
  if (!node) return null;
  if (node.type === "StringLiteral") return node.value;
  if (node.type === "TemplateLiteral" && node.expressions.length === 0 && node.quasis.length === 1) {
    return node.quasis[0]?.value.cooked ?? null;
  }
  return null;
}

function startOf(node: Node): number {
  return typeof node.start === "number" ? node.start : 0;
}

function collectImport(node: ImportDeclaration, b: Bindings): void {
  const src = node.source.value;
  const isCrypto = src === "crypto" || src === "node:crypto";
  const isJwt = src === "jsonwebtoken";
  if (!isCrypto && !isJwt) return;
  for (const spec of node.specifiers) {
    if (spec.type === "ImportDefaultSpecifier" || spec.type === "ImportNamespaceSpecifier") {
      (isCrypto ? b.cryptoNs : b.jwtNs).add(spec.local.name);
    } else if (spec.type === "ImportSpecifier") {
      const imported = spec.imported.type === "Identifier" ? spec.imported.name : spec.imported.value;
      if (isCrypto && (HASH_METHODS.has(imported) || CIPHER_METHODS.has(imported))) {
        b.cryptoDirect.set(spec.local.name, imported);
      } else if (isJwt && JWT_METHODS.has(imported)) {
        b.jwtDirect.set(spec.local.name, imported);
      }
    }
  }
}

function collectRequire(node: VariableDeclarator, b: Bindings): void {
  const init = node.init;
  if (!init || init.type !== "CallExpression") return;
  if (init.callee.type !== "Identifier" || init.callee.name !== "require") return;
  const arg0 = init.arguments[0];
  const src = arg0 && arg0.type === "StringLiteral" ? arg0.value : null;
  const isCrypto = src === "crypto" || src === "node:crypto";
  const isJwt = src === "jsonwebtoken";
  if (!isCrypto && !isJwt) return;
  if (node.id.type === "Identifier") {
    (isCrypto ? b.cryptoNs : b.jwtNs).add(node.id.name);
  } else if (node.id.type === "ObjectPattern") {
    for (const prop of node.id.properties) {
      if (prop.type !== "ObjectProperty" || prop.key.type !== "Identifier" || prop.value.type !== "Identifier") {
        continue;
      }
      const method = prop.key.name;
      if (isCrypto && (HASH_METHODS.has(method) || CIPHER_METHODS.has(method))) {
        b.cryptoDirect.set(prop.value.name, method);
      } else if (isJwt && JWT_METHODS.has(method)) {
        b.jwtDirect.set(prop.value.name, method);
      }
    }
  }
}

function collectBindings(program: Program): Bindings {
  const b: Bindings = {
    cryptoNs: new Set(),
    cryptoDirect: new Map(),
    jwtNs: new Set(),
    jwtDirect: new Map(),
  };
  walk(program, (n) => {
    if (n.type === "ImportDeclaration") collectImport(n, b);
    else if (n.type === "VariableDeclarator") collectRequire(n, b);
  });
  return b;
}

function lastObjectArg(call: CallExpression): ObjectExpression | null {
  for (let i = call.arguments.length - 1; i >= 0; i -= 1) {
    const arg = call.arguments[i];
    if (arg && arg.type === "ObjectExpression") return arg;
  }
  return null;
}

function emitHash(alg: string, at: Node, tier: Confidence, hits: Hit[], push: PushFinding): void {
  const index = startOf(at);
  hits.push({
    index,
    emit: () =>
      push(
        "SRC",
        "high",
        "source",
        `Weak hash algorithm via node:crypto (${alg})`,
        index,
        "vulnerable",
        "Replace MD5/SHA-1 with SHA-256 or SHA-3; both are already collision-broken classically.",
        { tier, algorithm: /^md5$/i.test(alg) ? "MD5" : "SHA-1", references: [REFS.cwe327, REFS.sp800131a] },
      ),
  });
}

function emitCipher(alg: string, at: Node, tier: Confidence, hits: Hit[], push: PushFinding): void {
  const index = startOf(at);
  hits.push({
    index,
    emit: () =>
      push(
        "SRC",
        "high",
        "source",
        `Weak symmetric cipher via node:crypto (${alg})`,
        index,
        "vulnerable",
        "Replace DES/3DES/RC4/RC2 with AES-256-GCM and re-key affected data.",
        { tier, algorithm: alg.toUpperCase(), references: [REFS.cwe327] },
      ),
  });
}

function emitJwt(call: CallExpression, tier: Confidence, hits: Hit[], push: PushFinding): void {
  const options = lastObjectArg(call);
  if (!options) return;
  const consider = (node: Node | null | undefined): void => {
    const alg = staticString(node);
    if (!alg || !RECOGNIZED_JWT_ALGS.has(alg) || !node) return;
    const { severity, pq, note } = jwtAssessment(alg);
    const index = startOf(node);
    hits.push({
      index,
      emit: () =>
        push("JWT", severity, "jwt", `JSON Web Token algorithm ${alg}`, index, pq, note, {
          tier,
          algorithm: `JWT-${alg}`,
        }),
    });
  };
  for (const prop of options.properties) {
    if (prop.type !== "ObjectProperty" || prop.computed) continue;
    const key =
      prop.key.type === "Identifier" ? prop.key.name : prop.key.type === "StringLiteral" ? prop.key.value : null;
    if (key === "algorithm") {
      consider(prop.value);
    } else if (key === "algorithms" && prop.value.type === "ArrayExpression") {
      for (const el of prop.value.elements) consider(el);
    }
  }
}

function matchCall(call: CallExpression, b: Bindings, push: PushFinding, src: Hit[], jwt: Hit[]): void {
  const callee = call.callee;
  if (callee.type === "Identifier") {
    const method = b.cryptoDirect.get(callee.name);
    if (method) {
      const arg = staticString(call.arguments[0] as Node | null);
      if (arg && HASH_METHODS.has(method) && WEAK_HASH_ALG.test(arg)) emitHash(arg, call.arguments[0] as Node, "confirmed", src, push);
      else if (arg && CIPHER_METHODS.has(method) && WEAK_CIPHER_ALG.test(arg)) emitCipher(arg, call.arguments[0] as Node, "confirmed", src, push);
      return;
    }
    if (b.jwtDirect.has(callee.name)) emitJwt(call, "confirmed", jwt, push);
    return;
  }
  if (
    callee.type === "MemberExpression" &&
    !callee.computed &&
    callee.property.type === "Identifier" &&
    callee.object.type === "Identifier"
  ) {
    const method = callee.property.name;
    const obj = callee.object.name;
    if (HASH_METHODS.has(method) || CIPHER_METHODS.has(method)) {
      const tier: Confidence = b.cryptoNs.has(obj) ? "confirmed" : "high";
      const arg = staticString(call.arguments[0] as Node | null);
      if (arg && HASH_METHODS.has(method) && WEAK_HASH_ALG.test(arg)) emitHash(arg, call.arguments[0] as Node, tier, src, push);
      else if (arg && CIPHER_METHODS.has(method) && WEAK_CIPHER_ALG.test(arg)) emitCipher(arg, call.arguments[0] as Node, tier, src, push);
      return;
    }
    if (JWT_METHODS.has(method) && (b.jwtNs.has(obj) || obj === "jwt")) {
      emitJwt(call, b.jwtNs.has(obj) ? "confirmed" : "high", jwt, push);
    }
  }
}

/**
 * Structurally scan a JS/TS file. Returns `used: 'ast'` only when the file parsed
 * with zero errors, in which case hash/cipher/jwt findings have already been
 * pushed and the caller must not re-run those regexes for this file.
 */
export function scanJsAst(relPath: string, content: string, push: PushFinding): ScanJsResult {
  const fallback: ScanJsResult = { used: "fallback", stringRanges: [] };
  if (content.length > MAX_PARSE_BYTES) return fallback;

  let program: Program;
  try {
    const file = parse(content, { sourceType: "unambiguous", errorRecovery: true, plugins: pluginsFor(relPath) });
    if (file.errors && file.errors.length > 0) return fallback; // never trust a partially-recovered tree
    program = file.program;
  } catch {
    return fallback;
  }

  const bindings = collectBindings(program);
  const stringRanges: Array<[number, number]> = [];
  const srcHits: Hit[] = [];
  const jwtHits: Hit[] = [];

  walk(program, (n) => {
    if ((n.type === "StringLiteral" || n.type === "TemplateLiteral") && typeof n.start === "number" && typeof n.end === "number") {
      stringRanges.push([n.start, n.end]);
    }
    if (n.type === "CallExpression") matchCall(n, bindings, push, srcHits, jwtHits);
  });

  // Emit hash/cipher (SRC) grouped and line-ordered first, then JWT, so ids stay stable.
  for (const hit of srcHits.sort((a, z) => a.index - z.index)) hit.emit();
  for (const hit of jwtHits.sort((a, z) => a.index - z.index)) hit.emit();

  return { used: "ast", stringRanges };
}
