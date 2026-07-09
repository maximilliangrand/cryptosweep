import { describe, expect, it } from "vitest";
import { SELF } from "cloudflare:test";
describe("GET /", () => {
  it("returns 200 with HTML content-type", async () => {
    const res = await SELF.fetch("https://example.com/");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/^text\/html/);
  });

  it("body contains the email input and H1 headline", async () => {
    const res = await SELF.fetch("https://example.com/");
    const body = await res.text();
    expect(body).toContain('<input id="email" type="email"');
    expect(body).toContain("Post-quantum readiness for legal SaaS");
  });

  it("serves the /privacy page the footer links to (no longer a dead link)", async () => {
    const res = await SELF.fetch("https://example.com/privacy");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/^text\/html/);
    expect(await res.text()).toContain("Privacy");
  });
});
