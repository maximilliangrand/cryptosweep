import { beforeEach, describe, expect, it } from "vitest";
import { env, SELF } from "cloudflare:test";
import schema from "../src/storage/d1-schema.sql?raw";
import type { Env } from "../src/env";

const SCAN_URL = "https://example.com/api/scan-request";

function postForm(body: Record<string, string>, headers: Record<string, string> = {}): Promise<Response> {
  const params = new URLSearchParams(body);
  return SELF.fetch(SCAN_URL, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      "CF-Connecting-IP": "203.0.113.10",
      ...headers,
    },
    body: params.toString(),
  });
}

async function applySchema() {
  const db = (env as unknown as Env).DB;
  for (const stmt of schema.split(/;\s*\n/).map((s) => s.trim()).filter(Boolean)) {
    await db.exec(stmt.replace(/\n/g, " "));
  }
}

async function reset() {
  const db = (env as unknown as Env).DB;
  await applySchema();
  await db.exec("DELETE FROM scan_requests");
  await (env as unknown as Env).RL_KV.list().then(async (list) => {
    for (const key of list.keys) {
      await (env as unknown as Env).RL_KV.delete(key.name);
    }
  });
}

describe("POST /api/scan-request", () => {
  beforeEach(reset);

  it("accepts a valid request and stores a row", async () => {
    const res = await postForm({ email: "max@example.com", target: "example.com", company_url: "" });
    expect(res.status).toBe(202);
    const body = (await res.json()) as { ok: boolean; id: string };
    expect(body.ok).toBe(true);
    expect(body.id).toMatch(/^[0-9a-f-]{36}$/i);

    const db = (env as unknown as Env).DB;
    const row = await db
      .prepare("SELECT id, email, target, status FROM scan_requests WHERE id = ?")
      .bind(body.id)
      .first<{ id: string; email: string; target: string; status: string }>();
    expect(row?.email).toBe("max@example.com");
    expect(row?.target).toBe("example.com");
    expect(row?.status).toBe("pending");
  });

  it("rejects invalid email with 400 invalid_email", async () => {
    const res = await postForm({ email: "not-an-email", target: "example.com", company_url: "" });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_email");
  });

  it("rejects invalid target with 400 invalid_target", async () => {
    const res = await postForm({ email: "max@example.com", target: "not_a_domain", company_url: "" });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_target");
  });

  it("silently 202s when honeypot is filled, with no D1 row", async () => {
    const res = await postForm({
      email: "bot@example.com",
      target: "example.com",
      company_url: "https://malicious.example",
    });
    expect(res.status).toBe(202);

    const db = (env as unknown as Env).DB;
    const count = await db
      .prepare("SELECT COUNT(*) AS c FROM scan_requests")
      .first<{ c: number }>();
    expect(count?.c).toBe(0);
  });

  it("returns 429 after exceeding 5 requests in the window from the same IP", async () => {
    const ip = "198.51.100.42";
    const headers = { "CF-Connecting-IP": ip };
    for (let i = 0; i < 5; i++) {
      const ok = await postForm({ email: `u${i}@example.com`, target: "example.com", company_url: "" }, headers);
      expect(ok.status).toBe(202);
    }
    const blocked = await postForm(
      { email: "burst@example.com", target: "example.com", company_url: "" },
      headers,
    );
    expect(blocked.status).toBe(429);
    const body = (await blocked.json()) as { error: string };
    expect(body.error).toBe("rate_limited");
  });

  it("enforces the limit atomically under a concurrent burst (no race leak)", async () => {
    const headers = { "CF-Connecting-IP": "198.51.100.77" };
    // Fire 20 requests concurrently. A read-modify-write counter would let more
    // than 5 through; the Durable Object serializes them, so exactly 5 pass.
    const responses = await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        postForm({ email: `burst${i}@example.com`, target: "example.com", company_url: "" }, headers),
      ),
    );
    const accepted = responses.filter((r) => r.status === 202).length;
    const limited = responses.filter((r) => r.status === 429).length;
    expect(accepted).toBe(5);
    expect(limited).toBe(15);
  });
});
