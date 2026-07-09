/**
 * Self-contained HTML report viewer.
 *
 * The UI is a React + Blueprint (Palantir's open-source design system) app,
 * bundled offline into {@link ./viewer-shell} with everything inlined. Here we
 * only inject the report JSON into that shell as a JSON island; Blueprint/React
 * render it. Scanned repositories are untrusted, so the injected `<` is escaped
 * to keep the data from breaking out of its <script> tag, and React escapes
 * every value it renders.
 */
import type { Report } from "../report";
import { VIEWER_SHELL_B64, VIEWER_DATA_PLACEHOLDER } from "./viewer-shell";

/** Render a report as a single self-contained, offline HTML document. */
export function toHtml(report: Report): string {
  const shell = Buffer.from(VIEWER_SHELL_B64, "base64").toString("utf8");
  const data = JSON.stringify(report).replace(/</g, "\\u003c");
  // Use a replacer function so `$` sequences in the data are treated literally.
  return shell.replace(VIEWER_DATA_PLACEHOLDER, () => data);
}
