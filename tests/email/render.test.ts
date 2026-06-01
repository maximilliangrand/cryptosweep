import { describe, expect, it } from "vitest";
import { renderHtml, renderText } from "../../src/email/render";
import { buildReport } from "../../src/report";
import type { Finding } from "../../src/report";

const FINDINGS: Finding[] = [
  {
    id: "CSW-TLS-001",
    severity: "critical",
    category: "tls",
    title: "Leaf public key: RSA-2048",
    evidence: "vuln.example.com:443",
    pq_status: "vulnerable",
    recommendation: "Plan migration to hybrid ML-KEM / ML-DSA certificates per NIST SP 800-208.",
  },
  {
    id: "CSW-SRC-002",
    severity: "high",
    category: "source",
    title: "MD5 in node:crypto",
    evidence: "src/legacy/hash.ts:42",
    pq_status: "vulnerable",
    recommendation: "Replace MD5 with SHA-256 (FIPS 180-4) and consider SHA3 for new code.",
  },
  {
    id: "CSW-DEP-003",
    severity: "medium",
    category: "deps",
    title: "Dependency: jsonwebtoken",
    evidence: "package.json:jsonwebtoken@9.0.2",
    pq_status: "transitional",
    recommendation: "Migrate signing to ML-DSA (FIPS 204) once an ecosystem-supported library lands.",
  },
  {
    id: "CSW-DEP-004",
    severity: "low",
    category: "deps",
    title: "Dependency: rsa (python)",
    evidence: "requirements.txt:rsa@4.9",
    pq_status: "vulnerable",
    recommendation: "Track migration to hybrid / ML-KEM for any key exchange touched by this dep.",
  },
];

const REPORT = buildReport("example.com", FINDINGS, new Date("2026-05-30T12:00:00.000Z"));

describe("renderHtml", () => {
  it("matches a stable snapshot grouped by severity", () => {
    expect(renderHtml(REPORT)).toMatchSnapshot();
  });

  it("includes a severity heading and one finding block per finding", () => {
    const html = renderHtml(REPORT);
    expect(html).toContain("Critical (1)");
    expect(html).toContain("High (1)");
    expect(html).toContain("Medium (1)");
    expect(html).toContain("Low (1)");
    for (const finding of FINDINGS) {
      expect(html).toContain(finding.id);
      expect(html).toContain(finding.recommendation);
    }
  });

  it("escapes HTML-special characters in evidence", () => {
    const report = buildReport("example.com", [
      {
        ...FINDINGS[0]!,
        evidence: "<script>alert(1)</script>",
      },
    ]);
    const html = renderHtml(report);
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });

  it("renders a friendly empty state when there are no findings", () => {
    const empty = buildReport("clean.example.com", [], new Date("2026-05-30T12:00:00.000Z"));
    const html = renderHtml(empty);
    expect(html).toContain("No quantum-vulnerable primitives detected.");
  });
});

describe("renderText", () => {
  it("matches a stable snapshot grouped by severity", () => {
    expect(renderText(REPORT)).toMatchSnapshot();
  });

  it("groups findings under severity headings in critical→low order", () => {
    const text = renderText(REPORT);
    const critIdx = text.indexOf("Critical (1)");
    const highIdx = text.indexOf("High (1)");
    const medIdx = text.indexOf("Medium (1)");
    const lowIdx = text.indexOf("Low (1)");
    expect(critIdx).toBeGreaterThan(-1);
    expect(critIdx).toBeLessThan(highIdx);
    expect(highIdx).toBeLessThan(medIdx);
    expect(medIdx).toBeLessThan(lowIdx);
  });

  it("mentions NIST in the footer for every report", () => {
    expect(renderText(REPORT)).toContain("NIST");
  });
});
