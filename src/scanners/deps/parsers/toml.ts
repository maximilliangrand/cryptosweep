/**
 * Minimal TOML reader for dependency manifests.
 *
 * Covers what Cargo.toml, Cargo.lock, pyproject.toml, poetry.lock, uv.lock and
 * Pipfile use: `[tables]` and `[[arrays of tables]]` with dotted and quoted
 * keys, dotted keys in key/value pairs, basic and literal strings (single- and
 * multi-line, with escapes), integers, floats, booleans, dates (kept as
 * strings), arrays (multi-line, trailing commas, comments) and inline tables.
 *
 * The regex scrapers this replaces stopped a dependency array at the first
 * `]` (so `"cryptography[ssh]>=41"` emptied the whole list) and only knew
 * exact `[dependencies]` headers. Here a malformed statement is skipped to the
 * end of its line instead of aborting the file, so one odd line cannot drop
 * every dependency. One forward pass, bounded nesting, no regex backtracking.
 * Pure / no I/O.
 */
export type TomlValue = string | number | boolean | TomlValue[] | TomlTable;

export interface TomlTable {
  [key: string]: TomlValue | undefined;
}

const MAX_DEPTH = 64;

class TomlSyntaxError extends Error {}

/** Null-prototype, so a `__proto__` key in a hostile manifest is an ordinary key. */
function newTable(): TomlTable {
  return Object.create(null) as TomlTable;
}

export function isTable(value: TomlValue | undefined): value is TomlTable {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** `value` as a table, or null. */
export function tableOf(value: TomlValue | undefined): TomlTable | null {
  return isTable(value) ? value : null;
}

/** `value` as an array, or empty. */
export function arrayOf(value: TomlValue | undefined): TomlValue[] {
  return Array.isArray(value) ? value : [];
}

/** The string elements of an array value. */
export function stringsOf(value: TomlValue | undefined): string[] {
  return arrayOf(value).filter((item): item is string => typeof item === "string");
}

export function stringOf(value: TomlValue | undefined): string | undefined {
  return typeof value === "string" ? value : undefined;
}

const BARE_KEY = /[A-Za-z0-9_-]/;
const ESCAPES: Readonly<Record<string, string>> = { b: "\b", t: "\t", n: "\n", f: "\f", r: "\r", e: "\x1b", '"': '"', "\\": "\\" };

class Parser {
  private pos = 0;
  private readonly root = newTable();
  private current: TomlTable;

  constructor(private readonly src: string) {
    this.current = this.root;
  }

  parse(): TomlTable {
    while (this.pos < this.src.length) {
      try {
        this.statement();
      } catch (err) {
        if (!(err instanceof TomlSyntaxError)) throw err;
        this.skipLine();
      }
    }
    return this.root;
  }

  // ----- lexical helpers -----

  private peek(offset = 0): string | undefined {
    return this.src[this.pos + offset];
  }

  private fail(message: string): never {
    throw new TomlSyntaxError(message);
  }

  private skipSpaces(): void {
    while (this.peek() === " " || this.peek() === "\t") this.pos += 1;
  }

  private skipComment(): void {
    if (this.peek() !== "#") return;
    const end = this.src.indexOf("\n", this.pos);
    this.pos = end < 0 ? this.src.length : end;
  }

  /** Whitespace, newlines and comments (inside arrays and inline tables). */
  private skipBlank(): void {
    for (;;) {
      const c = this.peek();
      if (c === " " || c === "\t" || c === "\n" || c === "\r") this.pos += 1;
      else if (c === "#") this.skipComment();
      else return;
    }
  }

  private skipLine(): void {
    const end = this.src.indexOf("\n", this.pos);
    this.pos = end < 0 ? this.src.length : end + 1;
  }

  private expectLineEnd(): void {
    this.skipSpaces();
    this.skipComment();
    const c = this.peek();
    if (c === undefined) return;
    if (c === "\r" && this.peek(1) === "\n") this.pos += 2;
    else if (c === "\n") this.pos += 1;
    else this.fail("expected end of line");
  }

  // ----- statements -----

  private statement(): void {
    this.skipSpaces();
    const c = this.peek();
    if (c === undefined) return;
    if (c === "\n" || c === "\r" || c === "#") {
      this.skipComment();
      this.expectLineEnd();
      return;
    }
    if (c === "[") {
      this.header();
    } else {
      this.keyValue(this.current, 0);
    }
    this.expectLineEnd();
  }

  private header(): void {
    // Until the header parses, keys go to a detached table, not the previous one.
    this.current = newTable();
    const arrayTable = this.peek(1) === "[";
    this.pos += arrayTable ? 2 : 1;
    this.skipSpaces();
    const path = this.keyPath();
    this.skipSpaces();
    if (arrayTable ? !this.src.startsWith("]]", this.pos) : this.peek() !== "]") this.fail("unterminated table header");
    this.pos += arrayTable ? 2 : 1;
    const parent = this.descend(this.root, path.slice(0, -1));
    const last = path[path.length - 1] ?? this.fail("empty table header");
    const existing = parent[last];
    if (arrayTable) {
      const entry = newTable();
      if (existing === undefined) parent[last] = [entry];
      else if (Array.isArray(existing)) existing.push(entry);
      else this.fail("array table redefines a value");
      this.current = entry;
      return;
    }
    if (existing === undefined) {
      const table = newTable();
      parent[last] = table;
      this.current = table;
    } else {
      this.current = this.containerOf(existing);
    }
  }

  /** Walk (creating) nested tables; an array of tables continues in its last element. */
  private descend(from: TomlTable, path: readonly string[]): TomlTable {
    let table = from;
    for (const key of path) {
      const existing = table[key];
      if (existing === undefined) {
        const created = newTable();
        table[key] = created;
        table = created;
      } else {
        table = this.containerOf(existing);
      }
    }
    return table;
  }

  private containerOf(value: TomlValue): TomlTable {
    if (isTable(value)) return value;
    if (Array.isArray(value)) {
      const last = value[value.length - 1];
      if (isTable(last)) return last;
    }
    return this.fail("key is not a table");
  }

  private keyValue(into: TomlTable, depth: number): void {
    const path = this.keyPath();
    this.skipSpaces();
    if (this.peek() !== "=") this.fail("expected '='");
    this.pos += 1;
    this.skipSpaces();
    const value = this.value(depth);
    const target = this.descend(into, path.slice(0, -1));
    const last = path[path.length - 1] ?? this.fail("empty key");
    target[last] = value;
  }

  private keyPath(): string[] {
    const path = [this.key()];
    for (;;) {
      this.skipSpaces();
      if (this.peek() !== ".") return path;
      this.pos += 1;
      this.skipSpaces();
      path.push(this.key());
    }
  }

  private key(): string {
    const c = this.peek();
    if (c === '"') return this.basicString();
    if (c === "'") return this.literalString();
    const start = this.pos;
    while (this.peek() !== undefined && BARE_KEY.test(this.peek() ?? "")) this.pos += 1;
    if (this.pos === start) this.fail("expected a key");
    return this.src.slice(start, this.pos);
  }

  // ----- values -----

  private value(depth: number): TomlValue {
    if (depth > MAX_DEPTH) this.fail("nesting too deep");
    const c = this.peek();
    if (c === '"') return this.src.startsWith('"""', this.pos) ? this.multilineBasic() : this.basicString();
    if (c === "'") return this.src.startsWith("'''", this.pos) ? this.multilineLiteral() : this.literalString();
    if (c === "[") return this.array(depth);
    if (c === "{") return this.inlineTable(depth);
    return this.scalar();
  }

  private basicString(): string {
    this.pos += 1;
    let out = "";
    for (;;) {
      const c = this.peek();
      if (c === undefined || c === "\n") this.fail("unterminated string");
      this.pos += 1;
      if (c === '"') return out;
      out += c === "\\" ? this.escape() : c;
    }
  }

  private escape(): string {
    const c = this.peek();
    this.pos += 1;
    if (c === "u" || c === "U") {
      const length = c === "u" ? 4 : 8;
      const hex = this.src.slice(this.pos, this.pos + length);
      if (!/^[0-9A-Fa-f]+$/.test(hex) || hex.length !== length) this.fail("bad unicode escape");
      this.pos += length;
      const code = Number.parseInt(hex, 16);
      return code <= 0x10ffff ? String.fromCodePoint(code) : this.fail("bad unicode escape");
    }
    const escaped = c === undefined ? undefined : ESCAPES[c];
    return escaped ?? this.fail("bad escape");
  }

  private literalString(): string {
    this.pos += 1;
    const end = this.src.indexOf("'", this.pos);
    const newline = this.src.indexOf("\n", this.pos);
    if (end < 0 || (newline >= 0 && newline < end)) this.fail("unterminated string");
    const out = this.src.slice(this.pos, end);
    this.pos = end + 1;
    return out;
  }

  /** Skip the newline that may immediately follow an opening `"""` / `'''`. */
  private skipOpeningNewline(): void {
    if (this.peek() === "\n") this.pos += 1;
    else if (this.peek() === "\r" && this.peek(1) === "\n") this.pos += 2;
  }

  /** Consume a closing run of 3 to 5 quotes; the extra 1-2 belong to the content. */
  private closingQuotes(quote: string): string {
    let run = 0;
    while (this.peek() === quote && run < 5) {
      this.pos += 1;
      run += 1;
    }
    return quote.repeat(run - 3);
  }

  private multilineBasic(): string {
    this.pos += 3;
    this.skipOpeningNewline();
    let out = "";
    for (;;) {
      const c = this.peek();
      if (c === undefined) this.fail("unterminated string");
      if (this.src.startsWith('"""', this.pos)) return out + this.closingQuotes('"');
      this.pos += 1;
      if (c !== "\\") {
        out += c;
        continue;
      }
      const next = this.peek();
      if (next === " " || next === "\t" || next === "\n" || next === "\r") {
        // Line-ending backslash: trim all whitespace and newlines that follow.
        while (this.peek() === " " || this.peek() === "\t" || this.peek() === "\n" || this.peek() === "\r") this.pos += 1;
        continue;
      }
      out += this.escape();
    }
  }

  private multilineLiteral(): string {
    this.pos += 3;
    this.skipOpeningNewline();
    const end = this.src.indexOf("'''", this.pos);
    if (end < 0) this.fail("unterminated string");
    const out = this.src.slice(this.pos, end);
    this.pos = end;
    return out + this.closingQuotes("'");
  }

  private array(depth: number): TomlValue[] {
    this.pos += 1;
    const items: TomlValue[] = [];
    for (;;) {
      this.skipBlank();
      if (this.peek() === "]") {
        this.pos += 1;
        return items;
      }
      items.push(this.value(depth + 1));
      this.skipBlank();
      if (this.peek() === ",") this.pos += 1;
      else if (this.peek() !== "]") this.fail("expected ',' or ']'");
    }
  }

  private inlineTable(depth: number): TomlTable {
    this.pos += 1;
    const table = newTable();
    for (;;) {
      this.skipBlank();
      if (this.peek() === "}") {
        this.pos += 1;
        return table;
      }
      this.keyValue(table, depth + 1);
      this.skipBlank();
      if (this.peek() === ",") this.pos += 1;
      else if (this.peek() !== "}") this.fail("expected ',' or '}'");
    }
  }

  /** Booleans, numbers, and dates/times (kept as their source text). */
  private scalar(): TomlValue {
    const start = this.pos;
    for (;;) {
      const c = this.peek();
      if (c === undefined || c === "," || c === "]" || c === "}" || c === "#" || c === "\n" || c === "\r" || c === "\t") break;
      // A space ends the token, except inside an RFC 3339 date-time ("1979-05-27 07:32:00").
      if (c === " " && !(/^\d{4}-\d{2}-\d{2}$/.test(this.src.slice(start, this.pos)) && /\d/.test(this.peek(1) ?? ""))) break;
      this.pos += 1;
    }
    const token = this.src.slice(start, this.pos);
    if (token === "") this.fail("expected a value");
    if (token === "true") return true;
    if (token === "false") return false;
    const plain = token.replace(/_/g, "");
    if (/^[+-]?(?:inf|nan)$/.test(plain)) return plain.includes("nan") ? Number.NaN : plain.startsWith("-") ? -Infinity : Infinity;
    if (/^0x[0-9A-Fa-f]+$|^0o[0-7]+$|^0b[01]+$/.test(plain)) return Number(plain);
    if (/^[+-]?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(plain)) return Number(plain);
    // Offset/local date-times, dates and times are kept as their source text.
    if (/^\d{4}-\d{2}-\d{2}(?:[Tt ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:[Zz]|[+-]\d{2}:\d{2})?)?$|^\d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(token)) {
      return token;
    }
    return this.fail("expected a value");
  }
}

/** Parse a TOML document, best effort: a malformed statement is skipped, never fatal. */
export function parseToml(source: string): TomlTable {
  return new Parser(source).parse();
}
