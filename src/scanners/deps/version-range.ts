/**
 * Declared version constraints, read just far enough to answer one question:
 * does this declaration resolve below a given release, at or above it, or
 * could it go either way?
 *
 * npm, Cargo and PEP 440 share most of their shapes: `^`, `~`, `~=`, the
 * comparison operators, `==` / `=` / `===`, wildcards and x-ranges
 * (`41.*`, `0.23.x`), conjunctions separated by commas or spaces, npm's `||`
 * alternatives and `a - b` hyphen ranges. A bare version is exact (npm,
 * lockfiles) unless it is partial, where `0.23` means `0.23.x`; the Cargo
 * parser makes Cargo's bare-version caret explicit. Pre-release and build
 * suffixes are ignored. Anything else is unreadable (null), never guessed.
 * Pure, and linear in the length of the declaration.
 */

export type RangeVerdict =
  /** Every version the declaration admits is at or above the release. */
  | { kind: "at-or-above" }
  /** Every version it admits is below the release; `exact` for a single pinned version. */
  | { kind: "below"; exact: boolean }
  /** It admits versions on both sides, so the installed version decides. */
  | { kind: "either" };

interface Bound {
  version: number[];
  inclusive: boolean;
}

interface Interval {
  lower: Bound | null;
  upper: Bound | null;
  exact: boolean;
}

const COMPARATOR = /^(===|==|~=|!=|>=|<=|>|<|=|\^|~)?v?(\d{1,9}(?:\.\d{1,9}){0,5})(?:\.([*xX]))?(?:[-+.]?[0-9A-Za-z][0-9A-Za-z.+-]{0,63})?$/;
const ANY = /^(?:\*|[xX])?$/;
const MAX_ALTERNATIVES = 16;

export function compareVersions(a: readonly number[], b: readonly number[]): number {
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i += 1) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/** `parts` with the component at `index` incremented and everything after it dropped. */
function bump(parts: readonly number[], index: number): number[] {
  return [...parts.slice(0, index), (parts[index] ?? 0) + 1];
}

/** Semver caret: the first non-zero component may not change (`^0.23.1` is `<0.24.0`). */
function caretUpper(parts: readonly number[]): number[] {
  const nonZero = parts.findIndex((n) => n !== 0);
  return bump(parts, nonZero < 0 ? parts.length - 1 : nonZero);
}

function interval(lower: Bound | null, upper: Bound | null, exact = false): Interval {
  return { lower, upper, exact };
}

/** One comparator as an interval, or null when it cannot be read. */
function comparator(token: string): Interval | null {
  if (ANY.test(token)) return interval(null, null);
  const match = COMPARATOR.exec(token);
  if (!match?.[2]) return null;
  const op = match[1] ?? "";
  const parts = match[2].split(".").map(Number);
  const at = (version: number[], inclusive = true): Bound => ({ version, inclusive });
  const wildcard = match[3] !== undefined || (op === "" && parts.length < 3);
  if (wildcard && (op === "" || op === "=" || op === "==" || op === "===")) {
    return interval(at(parts), at(bump(parts, parts.length - 1), false));
  }
  switch (op) {
    case "":
    case "=":
    case "==":
    case "===":
      return interval(at(parts), at(parts), true);
    case "^":
      return interval(at(parts), at(caretUpper(parts), false));
    case "~":
      return interval(at(parts), at(bump(parts, parts.length >= 2 ? 1 : 0), false));
    case "~=":
      return parts.length >= 2 ? interval(at(parts), at(bump(parts, parts.length - 2), false)) : null;
    case ">=":
      return interval(at(parts), null);
    case ">":
      return interval(at(parts, false), null);
    case "<":
      return interval(null, at(parts, false));
    case "<=":
      return interval(null, at(parts));
    case "!=":
      return interval(null, null);
    default:
      return null;
  }
}

function tighterLower(a: Bound | null, b: Bound | null): Bound | null {
  if (!a || !b) return a ?? b;
  return compareVersions(a.version, b.version) >= 0 ? a : b;
}

function tighterUpper(a: Bound | null, b: Bound | null): Bound | null {
  if (!a || !b) return a ?? b;
  return compareVersions(a.version, b.version) <= 0 ? a : b;
}

/** A conjunction (`>=41,<47`, `>=1.2 <2`, `1.2 - 2.3`) as one interval. */
function conjunction(text: string): Interval | null {
  const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(text);
  const tokens = hyphen ? [`>=${hyphen[1] ?? ""}`, `<=${hyphen[2] ?? ""}`] : text.split(/\s*,\s*|\s+/).filter(Boolean);
  if (tokens.length === 0) return interval(null, null);
  let result: Interval = interval(null, null, tokens.length === 1);
  for (const token of tokens) {
    const next = comparator(token);
    if (!next) return null;
    result = {
      lower: tighterLower(result.lower, next.lower),
      upper: tighterUpper(result.upper, next.upper),
      exact: result.exact && next.exact,
    };
  }
  return result;
}

function judgeInterval(range: Interval, fixed: readonly number[]): RangeVerdict {
  if (range.lower && compareVersions(range.lower.version, fixed) >= 0) return { kind: "at-or-above" };
  if (!range.upper) return { kind: "either" };
  const order = compareVersions(fixed, range.upper.version);
  const fixedAdmitted = order < 0 || (order === 0 && range.upper.inclusive);
  return fixedAdmitted ? { kind: "either" } : { kind: "below", exact: range.exact };
}

/**
 * Where a declared constraint stands against `fixed`, or null when the
 * declaration cannot be read (a tag, a URL, a git or path dependency).
 */
export function judgeRange(spec: string, fixed: readonly number[]): RangeVerdict | null {
  const normalized = spec.trim().replace(/(===|==|~=|!=|>=|<=|>|<|=|\^|~)\s+/g, "$1");
  const alternatives = normalized.split("||").map((alt) => alt.trim());
  if (alternatives.length > MAX_ALTERNATIVES) return null;
  const verdicts: RangeVerdict[] = [];
  for (const alternative of alternatives) {
    const range = conjunction(alternative);
    if (!range) return null;
    verdicts.push(judgeInterval(range, fixed));
  }
  if (verdicts.every((v) => v.kind === "at-or-above")) return { kind: "at-or-above" };
  if (verdicts.every((v) => v.kind === "below")) {
    const [only] = verdicts;
    return { kind: "below", exact: verdicts.length === 1 && only?.kind === "below" && only.exact };
  }
  return { kind: "either" };
}
