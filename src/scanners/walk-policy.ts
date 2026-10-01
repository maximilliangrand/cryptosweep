/**
 * What the directory walkers skip, and how a path's context is judged.
 *
 * The source and dependency scanners walk the same tree, so they share one
 * policy: a directory that holds installed dependencies, build output, a
 * virtual environment or a tool cache is not the project's own code, and a
 * file under a test, fixture, example or documentation tree may not be a live
 * code path. Keeping both decisions here means the two scanners can never
 * disagree about what a repository's own code is.
 */
import type { NonProductionContext } from "../report";

/**
 * Directory names skipped below the scan root. The root itself is never
 * skipped, so scanning one of these directories directly includes it.
 *
 * `env` is deliberately absent: it is a common name for configuration code.
 * A virtual environment under any name is caught by {@link SKIP_MARKERS}.
 */
export const DEFAULT_IGNORE_DIRS: ReadonlySet<string> = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "coverage",
  ".next",
  "out",
  "vendor",
  ".turbo",
  "target", // Rust (Cargo) and JVM (Maven) build output
  ".venv", // in-tree Python virtual environments
  "venv",
  ".tox",
  ".nox",
  "__pycache__",
  ".mypy_cache",
  ".pytest_cache",
  ".ruff_cache",
]);

/**
 * Files whose presence marks a whole directory as not the project's code: a
 * Python virtual environment (PEP 405 `pyvenv.cfg`, whatever the directory is
 * called) and a cache directory (the Cache Directory Tagging Specification's
 * `CACHEDIR.TAG`, which Cargo writes into `target/`).
 */
export const SKIP_MARKERS: ReadonlySet<string> = new Set(["pyvenv.cfg", "CACHEDIR.TAG"]);

/** Skipped directories not worth naming in coverage: version-control metadata holds no code to scan. */
export const UNREPORTED_SKIPS: ReadonlySet<string> = new Set([".git"]);

const DOCS_DIR = /(^|\/)docs?\//;
const TEST_DIR = /(^|\/)(tests?|__tests__|__mocks__|__fixtures__|fixtures?|examples?|e2e|mocks?)\//;

/**
 * The context a repository-relative path's directories give it: a
 * documentation tree, a test, fixture or example tree, or (null) production.
 * Only directories are read here, never the file name, so a manifest such as
 * `requirements.txt` is not mistaken for documentation.
 */
export function directoryContext(relPath: string): NonProductionContext | null {
  const p = relPath.toLowerCase();
  if (DOCS_DIR.test(p)) return "docs";
  if (TEST_DIR.test(p)) return "test";
  return null;
}
