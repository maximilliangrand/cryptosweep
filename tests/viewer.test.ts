import { describe, expect, it } from "vitest";
import { buildReport } from "../src/report";
import type { Finding } from "../src/report";
import { toHtml } from "../src/output/viewer";

const AT = new Date("2026-01-01T00:00:00.000Z");

describe("toHtml", () => {
  it("produces a self-contained document with no external requests", () => {
    const report = buildReport("example.com", [], AT);
    const html = toHtml(report);
    expect(html.startsWith("<!doctype html>")).toBe(true);
    // No external scripts, styles, fonts, or images — everything inlined.
    expect(html).not.toMatch(/<script[^>]+src=/i);
    expect(html).not.toMatch(/<link[^>]+href=/i);
    expect(html).not.toMatch(/https?:\/\/[^"']*\.(js|css|woff2?|png|jpg)/i);
  });

  it("embeds the report as a JSON island", () => {
    const findings: Finding[] = [
      {
        id: "CSW-TLS-001",
        severity: "high",
        category: "tls",
        title: "Leaf public key: RSA-2048",
        evidence: "example.com:443",
        pq_status: "vulnerable",
        confidence: "confirmed",
        algorithm: "RSA-2048",
        recommendation: "Migrate to ML-DSA.",
      },
    ];
    const html = toHtml(buildReport("example.com", findings, AT));
    expect(html).toContain('id="data"');
    expect(html).toContain("RSA-2048");
  });

  it("neutralizes a </script> breakout attempt in scanned evidence", () => {
    const findings: Finding[] = [
      {
        id: "CSW-KEY-001",
        severity: "critical",
        category: "keys",
        title: "Hardcoded private key block",
        evidence: '</script><img src=x onerror=alert(1)>:1',
        pq_status: "vulnerable",
        confidence: "high",
        recommendation: "Rotate.",
      },
    ];
    const html = toHtml(buildReport("evil/repo", findings, AT));
    // The raw closing tag must not appear unescaped inside the JSON island.
    expect(html).not.toContain("</script><img");
    expect(html).toContain("\\u003c/script>");
  });
});
