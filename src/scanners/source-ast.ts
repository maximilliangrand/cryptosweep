/**
 * AST-based source scanner for JavaScript and TypeScript.
 *
 * Files are parsed with @babel/parser (a devDependency inlined into the bundle
 * at build time) and every call is matched against the call table in
 * source-rules.ts, so a match comes from the syntax tree, never a substring:
 * `createHash("md5")` in a comment or an unrelated string does not fire.
 *
 * Callees are resolved through a minimal lexical scope model: imports,
 * `require()` (plain, destructured, aliased, inline), `await import()`, TS
 * `import x = require()`, `const` aliases (`const h = crypto.createHash`),
 * member chains (`globalThis.crypto.subtle.sign`), optional chaining, TS
 * wrappers (`as`, `!`, `satisfies`) and the `(0, fn)()` / interop-helper shapes
 * transpilers emit. Scopes follow the language: a parameter or local declared
 * in an inner function or block shadows the import, so the shadowed call is no
 * longer reported as resolved.
 *
 * A call is `confirmed` only when its callee resolves to a `const` or import
 * binding of the module. A binding through `let`/`var`, a shadowing local
 * named like the module, or a distinctive node:crypto method on an unresolved
 * receiver (`this.crypto.createHash`) is `high`.
 *
 * Not modelled: reassignment, values that flow through function calls or
 * mutable objects, and `eval`. Algorithm arguments resolve through `const`
 * string, array and object-literal bindings only.
 */
import { parse } from "@babel/parser";
import type {
  ArrayExpression,
  CallExpression,
  ImportDeclaration,
  MemberExpression,
  NewExpression,
  Node,
  ObjectExpression,
  ObjectProperty,
  OptionalCallExpression,
  OptionalMemberExpression,
  Program,
  Statement,
  VariableDeclarator,
} from "@babel/types";
import type { Confidence } from "../report";
import { JOSE_BUILDERS, JS_CALL_MATCHERS, roleOfName } from "./source-rules";
import type { CallFacts, HashRole, JsApi, JsArgument, JsCallMatcher, RuleHit } from "./source-rules";

const JS_TS_EXT = /\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)$/i;
const MAX_PARSE_BYTES = 1_000_000;
/** Nested resolution steps before a value is treated as unknown (bounds hostile alias chains). */
const MAX_RESOLVE_DEPTH = 64;
/** Names read from the surrounding code when judging a digest's role. */
const MAX_CONTEXT_NAMES = 24;
/** Statements after a digest's declaration searched for its uses, and the nodes walked there. */
const MAX_USE_STATEMENTS = 16;
const MAX_USE_NODES = 2_000;
/** Scalar properties read from one options / algorithm object. */
const MAX_OBJECT_PARAMS = 32;

export function isJsTsFile(relPath: string): boolean {
  return JS_TS_EXT.test(relPath);
}

export interface ScanJsResult {
  used: "ast" | "fallback";
  /** Rule matches, only meaningful when `used` is `ast`. */
  hits: RuleHit[];
  /** [start,end) offsets of every string/template literal, sorted by start, for in-literal key upgrades. */
  stringRanges: Array<[number, number]>;
}

type ModuleId = "node:crypto" | "jsonwebtoken" | "jose";

const MODULES: ReadonlyMap<string, ModuleId> = new Map([
  ["crypto", "node:crypto"],
  ["node:crypto", "node:crypto"],
  ["jsonwebtoken", "jsonwebtoken"],
  ["jose", "jose"],
]);

/** Browser / runtime global objects that expose `crypto` as a property. */
const GLOBAL_OBJECTS: ReadonlySet<string> = new Set(["window", "globalThis", "self", "global"]);

/** Helpers transpilers wrap `require()` in; they hand back the module (or `{ default: module }`). */
const INTEROP_HELPERS: ReadonlySet<string> = new Set([
  "_interopRequireDefault",
  "_interopRequireWildcard",
  "__importDefault",
  "__importStar",
]);

/** The symbolic value of an expression, as far as the scanner can tell statically. */
type Value =
  | { readonly kind: "module"; readonly module: ModuleId; readonly path: readonly string[]; readonly stable: boolean }
  | { readonly kind: "global"; readonly name: string; readonly path: readonly string[] }
  | { readonly kind: "local"; readonly name: string; readonly path: readonly string[] }
  | { readonly kind: "string"; readonly value: string }
  | { readonly kind: "number"; readonly value: number }
  | { readonly kind: "object"; readonly node: ObjectExpression; readonly scope: Scope }
  | { readonly kind: "array"; readonly node: ArrayExpression; readonly scope: Scope }
  | { readonly kind: "builder"; readonly className: string; readonly stable: boolean };

const UNKNOWN: Value = { kind: "local", name: "", path: [] };

function localValue(name: string): Value {
  return { kind: "local", name, path: [] };
}

/** A declared name whose value is computed on first use (declarations are hoisted, inits are lazy). */
class Binding {
  private value: Value | null = null;
  private resolving = false;

  constructor(
    private readonly name: string,
    private readonly compute: (() => Value) | null,
  ) {}

  get(): Value {
    if (this.value) return this.value;
    if (!this.compute || this.resolving) return localValue(this.name);
    this.resolving = true;
    try {
      const value = this.compute();
      // An unknown value keeps the declared name, so `const jwt = makeJwt()` still reads as `jwt`.
      this.value = value.kind === "local" && value.name === "" && value.path.length === 0 ? localValue(this.name) : value;
    } finally {
      this.resolving = false;
    }
    return this.value;
  }
}

class Scope {
  private readonly bindings = new Map<string, Binding>();

  constructor(private readonly parent: Scope | null) {}

  declare(name: string, binding: Binding): void {
    this.bindings.set(name, binding);
  }

  lookup(name: string): Binding | null {
    return this.bindings.get(name) ?? this.parent?.lookup(name) ?? null;
  }
}

function once(compute: () => Value): () => Value {
  let cached: Value | null = null;
  return () => (cached ??= compute());
}

/** A module value bound through `let`/`var` can be reassigned, so it is no longer `confirmed`. */
function withStability(value: Value, stable: boolean): Value {
  if ((value.kind === "module" || value.kind === "builder") && !stable) return { ...value, stable: false };
  return value;
}

type FunctionNode = Extract<
  Node,
  { type: "FunctionDeclaration" | "FunctionExpression" | "ArrowFunctionExpression" | "ObjectMethod" | "ClassMethod" | "ClassPrivateMethod" }
>;

const FUNCTION_TYPES: ReadonlySet<string> = new Set([
  "FunctionDeclaration",
  "FunctionExpression",
  "ArrowFunctionExpression",
  "ObjectMethod",
  "ClassMethod",
  "ClassPrivateMethod",
]);

function isFunctionNode(node: Node): node is FunctionNode {
  return FUNCTION_TYPES.has(node.type);
}

function isNode(value: unknown): value is Node {
  return typeof value === "object" && value !== null && typeof (value as { type?: unknown }).type === "string";
}

const SKIP_KEYS: ReadonlySet<string> = new Set([
  "loc",
  "start",
  "end",
  "range",
  "extra",
  "leadingComments",
  "trailingComments",
  "innerComments",
]);

/** Every child node, ignoring position and comment metadata. */
function forEachChild(node: Node, visit: (child: Node) => void): void {
  const record = node as unknown as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (SKIP_KEYS.has(key)) continue;
    const value = record[key];
    if (Array.isArray(value)) {
      for (const child of value) if (isNode(child)) visit(child);
    } else if (isNode(value)) {
      visit(value);
    }
  }
}

/** Strip type assertions, parentheses and `(0, fn)` sequences down to the expression that matters. */
function unwrap(node: Node): Node {
  let current = node;
  for (;;) {
    switch (current.type) {
      case "TSAsExpression":
      case "TSSatisfiesExpression":
      case "TSNonNullExpression":
      case "TSTypeAssertion":
      case "TSInstantiationExpression":
      case "ParenthesizedExpression":
        current = current.expression;
        break;
      case "SequenceExpression": {
        const last = current.expressions[current.expressions.length - 1];
        if (!last) return current;
        current = last;
        break;
      }
      default:
        return current;
    }
  }
}

function startOf(node: Node): number {
  return typeof node.start === "number" ? node.start : 0;
}

function propertyKey(prop: ObjectProperty): string | null {
  const key = prop.key;
  if (key.type === "StringLiteral") return key.value;
  if (prop.computed) return null;
  if (key.type === "Identifier") return key.name;
  if (key.type === "NumericLiteral") return String(key.value);
  return null;
}

type PropertyLookup = { kind: "found"; value: Node } | { kind: "missing" } | { kind: "unknown" };

/** Last-wins lookup; a later spread may override the key, which makes it unknown. */
function findProperty(object: ObjectExpression, key: string): PropertyLookup {
  for (let i = object.properties.length - 1; i >= 0; i -= 1) {
    const prop = object.properties[i];
    if (!prop) continue;
    if (prop.type === "SpreadElement") return { kind: "unknown" };
    if (prop.type === "ObjectProperty" && propertyKey(prop) === key) return { kind: "found", value: prop.value };
    if (prop.type === "ObjectMethod" && !prop.computed && prop.key.type === "Identifier" && prop.key.name === key) {
      return { kind: "unknown" };
    }
  }
  return { kind: "missing" };
}

// ---------------------------------------------------------------------------
// Role of a weak digest, inferred from the names around the call
// ---------------------------------------------------------------------------

function simpleName(node: Node | null | undefined): string | null {
  if (!node) return null;
  const inner = unwrap(node);
  if (inner.type === "Identifier") return inner.name;
  if (inner.type === "StringLiteral") return inner.value;
  if (inner.type === "MemberExpression" || inner.type === "OptionalMemberExpression") {
    if (!inner.computed) return inner.property.type === "Identifier" ? inner.property.name : null;
    return inner.property.type === "StringLiteral" ? inner.property.value : null; // headers["ETag"]
  }
  return null;
}

/** Concatenations unpacked when reading an argument's names (`key + GUID`), at most this deep. */
const MAX_CONCAT_DEPTH = 4;

/** The simple names an argument contributes: itself, or each operand of a string concatenation. */
function argumentNames(node: Node, add: (name: string | null) => void, depth = 0): void {
  const inner = unwrap(node);
  if (inner.type === "BinaryExpression" && inner.operator === "+" && depth < MAX_CONCAT_DEPTH) {
    if (inner.left.type !== "PrivateName") argumentNames(inner.left, add, depth + 1);
    argumentNames(inner.right, add, depth + 1);
    return;
  }
  add(simpleName(inner));
}

/** The statement list a declaration sits in, when it sits directly in one. */
function statementList(container: Node): readonly Node[] | null {
  switch (container.type) {
    case "Program":
    case "BlockStatement":
    case "StaticBlock":
      return container.body;
    case "SwitchCase":
      return container.consequent;
    default:
      return null;
  }
}

/** Names next to one use of a variable: the call it is passed to, what it is compared with or stored in. */
function neighbourNames(use: Node, parent: Node, add: (name: string | null) => void): void {
  switch (parent.type) {
    case "CallExpression":
    case "OptionalCallExpression":
    case "NewExpression":
      if (!parent.arguments.some((arg) => arg === use)) return;
      if (parent.callee.type !== "V8IntrinsicIdentifier") add(simpleName(parent.callee));
      for (const arg of parent.arguments) if (arg !== use) argumentNames(arg, add);
      return;
    case "BinaryExpression":
    case "LogicalExpression": {
      const other = parent.left === use ? parent.right : parent.left;
      if (other.type !== "PrivateName") add(simpleName(other));
      return;
    }
    case "AssignmentExpression":
      if (parent.right === use) add(simpleName(parent.left));
      return;
    case "VariableDeclarator":
    case "ObjectProperty":
      if ((parent.type === "VariableDeclarator" ? parent.init : parent.value) === use) add(declaredName(parent));
      return;
    default:
      return;
  }
}

function declaredName(node: Node | undefined): string | null {
  if (!node) return null;
  switch (node.type) {
    case "VariableDeclarator":
      return node.id.type === "Identifier" ? node.id.name : null;
    case "AssignmentExpression":
      return simpleName(node.left);
    case "ObjectProperty":
    case "ClassProperty":
      return node.computed ? null : simpleName(node.key);
    default:
      return null;
  }
}

function functionName(fn: FunctionNode, parent: Node | undefined): string | null {
  if ((fn.type === "FunctionDeclaration" || fn.type === "FunctionExpression") && fn.id) return fn.id.name;
  if ((fn.type === "ObjectMethod" || fn.type === "ClassMethod") && !fn.computed) return simpleName(fn.key);
  return declaredName(parent);
}

// ---------------------------------------------------------------------------
// The analyzer
// ---------------------------------------------------------------------------

interface Target {
  api: JsApi;
  method: string;
  tier: Confidence;
  /** Matched by name only; a non-distinctive method needs a receiver named like the module. */
  heuristic: boolean;
  namedReceiver: boolean;
  receiver?: string;
}

type CallLike = CallExpression | OptionalCallExpression | NewExpression;

function tierFor(stable: boolean): Confidence {
  return stable ? "confirmed" : "high";
}

/** The API a resolved callee value belongs to, if any. */
function apiOf(value: Value): Target | null {
  if (value.kind === "module") {
    const method = value.path[value.path.length - 1];
    if (!method) return null;
    const receiver = value.path.slice(0, -1);
    const base = { method, tier: tierFor(value.stable), heuristic: false, namedReceiver: false };
    if (value.module !== "node:crypto") return receiver.length === 0 ? { ...base, api: value.module } : null;
    if (receiver.length === 0) return { ...base, api: "node:crypto" };
    const subtle = receiver.join(".");
    return subtle === "subtle" || subtle === "webcrypto.subtle" ? { ...base, api: "webcrypto" } : null;
  }
  if (value.kind !== "global" && value.kind !== "local") return null;
  let chain = [value.name, ...value.path];
  let global = value.kind === "global";
  if (global && GLOBAL_OBJECTS.has(value.name)) chain = chain.slice(1);
  const method = chain[chain.length - 1];
  const receiver = chain.slice(0, -1);
  if (!method || receiver.length === 0) return null;
  global = global && receiver[0] === "crypto";
  const last = receiver[receiver.length - 1];
  if (last === "subtle") {
    const official = global && receiver.length === 2;
    return { api: "webcrypto", method, tier: official ? "confirmed" : "high", heuristic: false, namedReceiver: false };
  }
  // Name heuristics key on the receiver's own name: `jwt.sign`, `this.jwt.sign`, `deps.crypto.sign`.
  if (last === "jwt") return { api: "jsonwebtoken", method, tier: "high", heuristic: true, namedReceiver: true };
  return { api: "node:crypto", method, tier: "high", heuristic: true, namedReceiver: last === "crypto" };
}

const MATCHERS_BY_KEY: ReadonlyMap<string, readonly JsCallMatcher[]> = (() => {
  const map = new Map<string, JsCallMatcher[]>();
  for (const matcher of JS_CALL_MATCHERS) {
    for (const method of matcher.methods) {
      const key = `${matcher.api}|${method}|${matcher.construct === true}`;
      const list = map.get(key) ?? [];
      list.push(matcher);
      map.set(key, list);
    }
  }
  return map;
})();

interface ExtractedFacts {
  facts: CallFacts;
  at: number;
}

class Analyzer {
  readonly hits: RuleHit[] = [];
  private readonly ranges: Array<[number, number]> = [];
  private readonly ancestors: Node[] = [];
  private depth = 0;

  run(program: Program): void {
    const root = new Scope(null);
    for (const statement of program.body) this.hoistVars(statement, root);
    this.hoistLexical(program.body, root);
    this.ancestors.push(program);
    forEachChild(program, (child) => this.visit(child, root));
    this.ancestors.pop();
  }

  stringRanges(): Array<[number, number]> {
    return [...this.ranges].sort((a, z) => a[0] - z[0]);
  }

  // ----- declarations -----

  private declarePattern(scope: Scope, pattern: Node, compute: (() => Value) | null): void {
    switch (pattern.type) {
      case "Identifier":
        scope.declare(pattern.name, new Binding(pattern.name, compute));
        return;
      case "AssignmentPattern":
        this.declarePattern(scope, pattern.left, compute);
        return;
      case "ObjectPattern":
        for (const prop of pattern.properties) {
          if (prop.type === "RestElement") {
            this.declarePattern(scope, prop.argument, null);
            continue;
          }
          const key = propertyKey(prop);
          const inner = compute && key !== null ? once(() => this.member(compute(), key)) : null;
          this.declarePattern(scope, prop.value, inner);
        }
        return;
      case "ArrayPattern":
        for (const element of pattern.elements) if (element) this.declarePattern(scope, element, null);
        return;
      case "RestElement":
        this.declarePattern(scope, pattern.argument, null);
        return;
      case "TSParameterProperty":
        this.declarePattern(scope, pattern.parameter, null);
        return;
      default:
        return;
    }
  }

  private declareDeclarator(scope: Scope, declarator: VariableDeclarator, stable: boolean): void {
    const init = declarator.init;
    const compute = init ? once(() => withStability(this.resolve(init, scope), stable)) : null;
    this.declarePattern(scope, declarator.id, compute);
  }

  private declareImport(node: ImportDeclaration, scope: Scope): void {
    if (node.importKind === "type" || node.importKind === "typeof") return;
    const module = MODULES.get(node.source.value);
    for (const spec of node.specifiers) {
      const local = spec.local.name;
      if (spec.type === "ImportSpecifier" && (spec.importKind === "type" || spec.importKind === "typeof")) continue;
      if (!module) {
        scope.declare(local, new Binding(local, null));
        continue;
      }
      let path: string[] = [];
      if (spec.type === "ImportSpecifier") {
        const imported = spec.imported.type === "Identifier" ? spec.imported.name : spec.imported.value;
        path = imported === "default" && module !== "jose" ? [] : [imported];
      }
      const value: Value = { kind: "module", module, path, stable: true };
      scope.declare(local, new Binding(local, () => value));
    }
  }

  /** `var` declarations anywhere below `node`, stopping at nested functions (they have their own). */
  private hoistVars(node: Node, scope: Scope): void {
    if (isFunctionNode(node)) return;
    if (node.type === "VariableDeclaration" && node.kind === "var") {
      for (const declarator of node.declarations) this.declareDeclarator(scope, declarator, false);
    }
    forEachChild(node, (child) => this.hoistVars(child, scope));
  }

  /** Block-scoped declarations directly in a statement list. */
  private hoistLexical(statements: readonly Statement[], scope: Scope): void {
    for (const raw of statements) {
      const statement =
        raw.type === "ExportNamedDeclaration" || raw.type === "ExportDefaultDeclaration" ? raw.declaration : raw;
      if (!statement) continue;
      switch (statement.type) {
        case "VariableDeclaration":
          if (statement.kind === "var") break;
          for (const declarator of statement.declarations) {
            this.declareDeclarator(scope, declarator, statement.kind !== "let");
          }
          break;
        case "FunctionDeclaration":
        case "ClassDeclaration":
        case "TSDeclareFunction":
          if (statement.id) scope.declare(statement.id.name, new Binding(statement.id.name, null));
          break;
        case "ImportDeclaration":
          this.declareImport(statement, scope);
          break;
        case "TSImportEqualsDeclaration": {
          const reference = statement.moduleReference;
          const module = reference.type === "TSExternalModuleReference" ? MODULES.get(reference.expression.value) : undefined;
          const value: Value = module ? { kind: "module", module, path: [], stable: true } : localValue(statement.id.name);
          scope.declare(statement.id.name, new Binding(statement.id.name, () => value));
          break;
        }
        default:
          break;
      }
    }
  }

  // ----- resolution -----

  private resolve(node: Node | null | undefined, scope: Scope): Value {
    if (!node || this.depth >= MAX_RESOLVE_DEPTH) return UNKNOWN;
    this.depth += 1;
    try {
      return this.evaluate(unwrap(node), scope);
    } finally {
      this.depth -= 1;
    }
  }

  private evaluate(node: Node, scope: Scope): Value {
    switch (node.type) {
      case "Identifier":
        return scope.lookup(node.name)?.get() ?? { kind: "global", name: node.name, path: [] };
      case "StringLiteral":
        return { kind: "string", value: node.value };
      case "TemplateLiteral": {
        const cooked = node.expressions.length === 0 ? node.quasis[0]?.value.cooked : undefined;
        return typeof cooked === "string" ? { kind: "string", value: cooked } : UNKNOWN;
      }
      case "NumericLiteral":
        return { kind: "number", value: node.value };
      case "ObjectExpression":
        return { kind: "object", node, scope };
      case "ArrayExpression":
        return { kind: "array", node, scope };
      case "MemberExpression":
      case "OptionalMemberExpression": {
        const name = this.propertyName(node, scope);
        return name === null ? UNKNOWN : this.member(this.resolve(node.object, scope), name);
      }
      case "CallExpression":
      case "OptionalCallExpression":
        return this.callResult(node, scope);
      case "AwaitExpression":
        return this.resolve(node.argument, scope);
      case "NewExpression": {
        const ctor = this.resolve(node.callee, scope);
        const className = ctor.kind === "module" && ctor.module === "jose" && ctor.path.length === 1 ? ctor.path[0] : undefined;
        return className && JOSE_BUILDERS.has(className) ? { kind: "builder", className, stable: ctor.kind === "module" && ctor.stable } : UNKNOWN;
      }
      default:
        return UNKNOWN;
    }
  }

  private propertyName(node: MemberExpression | OptionalMemberExpression, scope: Scope): string | null {
    if (!node.computed) return node.property.type === "Identifier" ? node.property.name : null;
    const key = this.resolve(node.property, scope);
    return key.kind === "string" ? key.value : null;
  }

  private member(object: Value, name: string): Value {
    switch (object.kind) {
      case "module":
        // ESM interop: `mod.default` of a CommonJS module is the module itself.
        if (object.path.length === 0 && name === "default" && object.module !== "jose") return object;
        return { ...object, path: [...object.path, name] };
      case "global":
      case "local":
        return { ...object, path: [...object.path, name] };
      case "object": {
        const found = findProperty(object.node, name);
        return found.kind === "found" ? this.resolve(found.value, object.scope) : UNKNOWN;
      }
      case "builder":
        return object; // jose builder methods return the builder
      default:
        return UNKNOWN;
    }
  }

  private moduleFrom(arg: Node | undefined, scope: Scope): Value {
    const source = this.resolve(arg, scope);
    if (source.kind !== "string") return UNKNOWN;
    const module = MODULES.get(source.value);
    return module ? { kind: "module", module, path: [], stable: true } : localValue(`module:${source.value}`);
  }

  private callResult(call: CallExpression | OptionalCallExpression, scope: Scope): Value {
    const callee = call.callee;
    if (callee.type === "Import") return this.moduleFrom(call.arguments[0], scope);
    if (callee.type === "V8IntrinsicIdentifier" || callee.type === "Super") return UNKNOWN;
    const target = unwrap(callee);
    if (target.type === "Identifier" && !scope.lookup(target.name)) {
      if (target.name === "require") return this.moduleFrom(call.arguments[0], scope);
      if (INTEROP_HELPERS.has(target.name)) return this.resolve(call.arguments[0], scope);
    }
    const fn = this.resolve(callee, scope);
    return fn.kind === "builder" ? fn : UNKNOWN;
  }

  // ----- traversal -----

  private visit(node: Node, scope: Scope): void {
    this.ancestors.push(node);
    if ((node.type === "StringLiteral" || node.type === "TemplateLiteral") && typeof node.start === "number" && typeof node.end === "number") {
      this.ranges.push([node.start, node.end]);
    }
    if (node.type === "CallExpression" || node.type === "OptionalCallExpression") this.matchCall(node, scope, false);
    else if (node.type === "NewExpression") this.matchCall(node, scope, true);
    const inner = this.scopeFor(node, scope);
    forEachChild(node, (child) => this.visit(child, inner));
    this.ancestors.pop();
  }

  /** The scope a node's children are visited in (a new one for functions, blocks, loops, catch). */
  private scopeFor(node: Node, scope: Scope): Scope {
    if (isFunctionNode(node)) {
      const inner = new Scope(scope);
      if (node.type === "FunctionExpression" && node.id) inner.declare(node.id.name, new Binding(node.id.name, null));
      for (const param of node.params) this.declarePattern(inner, param, null);
      if (node.body.type === "BlockStatement") for (const statement of node.body.body) this.hoistVars(statement, inner);
      return inner;
    }
    switch (node.type) {
      case "BlockStatement":
      case "StaticBlock": {
        const inner = new Scope(scope);
        this.hoistLexical(node.body, inner);
        return inner;
      }
      case "ForStatement":
        if (node.init?.type === "VariableDeclaration" && node.init.kind !== "var") {
          const inner = new Scope(scope);
          this.hoistLexical([node.init], inner);
          return inner;
        }
        return scope;
      case "ForInStatement":
      case "ForOfStatement":
        if (node.left.type === "VariableDeclaration" && node.left.kind !== "var") {
          const inner = new Scope(scope);
          for (const declarator of node.left.declarations) this.declarePattern(inner, declarator.id, null);
          return inner;
        }
        return scope;
      case "CatchClause": {
        const inner = new Scope(scope);
        if (node.param) this.declarePattern(inner, node.param, null);
        return inner;
      }
      case "SwitchStatement": {
        const inner = new Scope(scope);
        this.hoistLexical(node.cases.flatMap((c) => c.consequent), inner);
        return inner;
      }
      case "ClassExpression":
        if (node.id) {
          const inner = new Scope(scope);
          inner.declare(node.id.name, new Binding(node.id.name, null));
          return inner;
        }
        return scope;
      default:
        return scope;
    }
  }

  // ----- matching -----

  private target(call: CallLike, scope: Scope, construct: boolean): Target | null {
    const callee = call.callee;
    if (callee.type === "Import" || callee.type === "Super" || callee.type === "V8IntrinsicIdentifier") return null;
    const node = unwrap(callee);
    if (construct) {
      const ctor = this.resolve(node, scope);
      const method = ctor.kind === "module" && ctor.module === "jose" && ctor.path.length === 1 ? ctor.path[0] : undefined;
      return method && ctor.kind === "module"
        ? { api: "jose", method, tier: tierFor(ctor.stable), heuristic: false, namedReceiver: false }
        : null;
    }
    if (node.type === "MemberExpression" || node.type === "OptionalMemberExpression") {
      const method = this.propertyName(node, scope);
      if (method === null) return null;
      const receiver = this.resolve(node.object, scope);
      if (receiver.kind === "builder") {
        return { api: "jose", method, tier: tierFor(receiver.stable), heuristic: false, namedReceiver: false, receiver: receiver.className };
      }
      return apiOf(this.member(receiver, method));
    }
    return apiOf(this.resolve(node, scope));
  }

  private matchCall(call: CallLike, scope: Scope, construct: boolean): void {
    const target = this.target(call, scope, construct);
    if (!target) return;
    const matchers = MATCHERS_BY_KEY.get(`${target.api}|${target.method}|${construct}`) ?? [];
    for (const matcher of matchers) {
      if (target.heuristic && !matcher.distinctive && !target.namedReceiver) continue;
      if ((matcher.receivers !== undefined) !== (target.receiver !== undefined)) continue;
      if (matcher.receivers && target.receiver && !matcher.receivers.includes(target.receiver)) continue;
      const role = matcher.needsRole ? this.hashRole() : null;
      for (const { facts, at } of this.extract(call, matcher.argument, scope, target, role)) {
        const selection = matcher.classify(facts);
        if (selection) this.hits.push({ index: at, tier: target.tier, selection });
      }
    }
  }

  private extract(
    call: CallLike,
    argument: JsArgument,
    scope: Scope,
    target: Target,
    role: { role: HashRole; signal: string } | null,
  ): ExtractedFacts[] {
    const base: CallFacts = {
      method: target.method,
      token: null,
      size: null,
      dynamic: false,
      absent: false,
      params: {},
      receiver: target.receiver,
      role: role?.role,
      roleSignal: role?.signal,
    };
    const callStart = startOf(call);
    if (argument.from === "call") return [{ facts: { ...base, absent: true }, at: callStart }];

    const arg = call.arguments[argument.index];
    if (!arg) return [{ facts: { ...base, absent: true }, at: callStart }];
    const at = startOf(arg);
    if (arg.type === "SpreadElement" || arg.type === "ArgumentPlaceholder") return [{ facts: { ...base, dynamic: true }, at }];

    if (argument.from === "value") {
      const params = argument.paramsAt === undefined ? {} : this.scalars(call.arguments[argument.paramsAt], scope);
      const value = this.resolve(arg, scope);
      if (value.kind === "string") return [{ facts: { ...base, token: value.value, params }, at }];
      if (value.kind === "number") return [{ facts: { ...base, size: value.value, params }, at }];
      return [{ facts: { ...base, dynamic: true, params }, at }];
    }

    if (argument.from === "algorithm") {
      const value = this.resolve(arg, scope);
      if (value.kind === "string") return [{ facts: { ...base, token: value.value }, at }];
      if (value.kind !== "object") return [{ facts: { ...base, dynamic: true }, at }];
      const params = this.scalars(arg, scope);
      const name = params.name;
      return typeof name === "string"
        ? [{ facts: { ...base, token: name, params }, at }]
        : [{ facts: { ...base, dynamic: true, params }, at }];
    }

    return this.optionTokens(arg, argument.keys, scope, base);
  }

  /** Algorithm tokens from an options object: one entry per static string, plus a dynamic marker. */
  private optionTokens(arg: Node, keys: readonly string[], scope: Scope, base: CallFacts): ExtractedFacts[] {
    const at = startOf(arg);
    if (isFunctionNode(unwrap(arg))) return [{ facts: { ...base, absent: true }, at }]; // a callback in the options slot
    const options = this.resolve(arg, scope);
    if (options.kind !== "object") return [{ facts: { ...base, dynamic: true }, at }];
    const out: ExtractedFacts[] = [];
    let dynamic = false;
    for (const key of keys) {
      const found = findProperty(options.node, key);
      if (found.kind === "unknown") dynamic = true;
      if (found.kind !== "found") continue;
      const value = this.resolve(found.value, options.scope);
      if (value.kind === "string") {
        out.push({ facts: { ...base, token: value.value }, at: startOf(found.value) });
      } else if (value.kind === "array") {
        for (const element of value.node.elements) {
          if (!element) continue;
          const item = element.type === "SpreadElement" ? UNKNOWN : this.resolve(element, value.scope);
          if (item.kind === "string") out.push({ facts: { ...base, token: item.value }, at: startOf(element) });
          else dynamic = true;
        }
      } else {
        dynamic = true;
      }
    }
    if (dynamic) out.push({ facts: { ...base, dynamic: true }, at });
    return out.length > 0 ? out : [{ facts: { ...base, absent: true }, at }];
  }

  /** Static string/number properties of an object argument; `{ name }` values are flattened (WebCrypto `hash`). */
  private scalars(arg: Node | undefined, scope: Scope): Record<string, string | number> {
    const params: Record<string, string | number> = {};
    const value = arg && arg.type !== "SpreadElement" ? this.resolve(arg, scope) : UNKNOWN;
    if (value.kind !== "object") return params;
    for (const prop of value.node.properties.slice(0, MAX_OBJECT_PARAMS)) {
      if (prop.type !== "ObjectProperty") continue;
      const key = propertyKey(prop);
      if (key === null) continue;
      const v = this.resolve(prop.value, value.scope);
      if (v.kind === "string" || v.kind === "number") {
        params[key] = v.value;
      } else if (v.kind === "object") {
        const name = findProperty(v.node, "name");
        const nameValue = name.kind === "found" ? this.resolve(name.value, v.scope) : UNKNOWN;
        if (nameValue.kind === "string") params[key] = nameValue.value;
      }
    }
    return params;
  }

  /**
   * Names in the code around the current call (the variables and properties
   * it is assigned to, the calls it feeds, the enclosing function, and where
   * the variable it is assigned to is used next), used to tell a password hash
   * from an ETag. A security word anywhere wins.
   */
  private hashRole(): { role: HashRole; signal: string } | null {
    let nonSecurity: string | null = null;
    for (const name of this.contextNames()) {
      const role = roleOfName(name);
      if (role === "security") return { role, signal: name };
      if (role === "non-security" && nonSecurity === null) nonSecurity = name;
    }
    return nonSecurity === null ? null : { role: "non-security", signal: nonSecurity };
  }

  private contextNames(): string[] {
    const names: string[] = [];
    const add = (name: string | null): void => {
      if (name && names.length < MAX_CONTEXT_NAMES) names.push(name);
    };
    let declarator: { index: number; name: string } | null = null;
    for (let i = this.ancestors.length - 2; i >= 0 && names.length < MAX_CONTEXT_NAMES; i -= 1) {
      const node = this.ancestors[i];
      if (!node || node.type === "Program") break;
      if (isFunctionNode(node)) {
        add(functionName(node, this.ancestors[i - 1]));
        break;
      }
      if (node.type === "CallExpression" || node.type === "OptionalCallExpression" || node.type === "NewExpression") {
        if (node.callee.type !== "V8IntrinsicIdentifier") add(simpleName(node.callee));
        for (const arg of node.arguments) argumentNames(arg, add);
        continue;
      }
      if (!declarator && node.type === "VariableDeclarator" && node.id.type === "Identifier") {
        declarator = { index: i, name: node.id.name };
      }
      add(declaredName(node));
    }
    if (declarator) this.useSiteNames(declarator.index, declarator.name, add);
    return names;
  }

  /**
   * Names around the uses of the variable a digest is assigned to, in the
   * statements after its declaration: `res.setHeader("ETag", digest)`,
   * `if (secWSAccept !== digest)`. Bounded, and blind to shadowing in a
   * nested block, which at worst adds a name from an unrelated variable.
   */
  private useSiteNames(declaratorIndex: number, name: string, add: (name: string | null) => void): void {
    const declaration = this.ancestors[declaratorIndex - 1];
    const container = this.ancestors[declaratorIndex - 2];
    const statements = container ? statementList(container) : null;
    const at = declaration && statements ? statements.indexOf(declaration) : -1;
    if (!statements || at < 0) return;
    let budget = MAX_USE_NODES;
    const visit = (node: Node, parent: Node | null): void => {
      if (budget <= 0) return;
      budget -= 1;
      if (parent && node.type === "Identifier" && node.name === name) neighbourNames(node, parent, add);
      forEachChild(node, (child) => visit(child, node));
    };
    for (const statement of statements.slice(at + 1, at + 1 + MAX_USE_STATEMENTS)) visit(statement, null);
  }
}

type Plugin = "typescript" | "jsx" | "decorators-legacy";

function pluginsFor(relPath: string): Plugin[] {
  const p = relPath.toLowerCase();
  if (/\.(?:ts|mts|cts)$/.test(p)) return ["typescript", "decorators-legacy"];
  if (/\.tsx$/.test(p)) return ["typescript", "jsx", "decorators-legacy"];
  return ["jsx"];
}

/**
 * Structurally scan a JS/TS file. Returns `used: 'ast'` only when the file
 * parsed with zero errors and the analysis completed; the caller must then not
 * re-run the regex sweep for this file. Anything else (a parse error, a file
 * over the parse limit, a tree too deep to walk) falls back to the regexes.
 */
export function scanJsAst(relPath: string, content: string): ScanJsResult {
  const fallback: ScanJsResult = { used: "fallback", hits: [], stringRanges: [] };
  if (content.length > MAX_PARSE_BYTES) return fallback;

  let program: Program;
  try {
    const file = parse(content, { sourceType: "unambiguous", errorRecovery: true, plugins: pluginsFor(relPath) });
    if (file.errors && file.errors.length > 0) return fallback; // never trust a partially-recovered tree
    program = file.program;
  } catch {
    return fallback;
  }

  const analyzer = new Analyzer();
  try {
    analyzer.run(program);
  } catch {
    return fallback; // e.g. a pathologically deep tree overflowing the stack: the linear regex sweep still runs
  }
  return { used: "ast", hits: analyzer.hits, stringRanges: analyzer.stringRanges() };
}
