import { checkRateLimitDurable } from "../lib/rate-limiter-do";
import { hashIp } from "../lib/ip-hash";
import {
  parseBody,
  validateEmail,
  validateHoneypot,
  validateTarget,
} from "../lib/validate";
import { buildScanRequestEmbed, postDiscordWebhook } from "../lib/discord-webhook";
import type { Env } from "../env";

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

export async function handleScanRequest(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const ip = req.headers.get("CF-Connecting-IP") ?? req.headers.get("X-Forwarded-For") ?? "0.0.0.0";
  const ipHash = await hashIp(env.IP_HASH_SECRET, ip);
  const now = Date.now();

  const limit = await checkRateLimitDurable(env.RATE_LIMITER, ipHash);
  if (!limit.ok) {
    return jsonResponse(429, { error: "rate_limited", retry_after: limit.resetSeconds });
  }

  const parsed = await parseBody(req);
  if (!parsed) return jsonResponse(400, { error: "invalid_body" });

  if (!validateHoneypot(parsed.company_url)) {
    return jsonResponse(202, { ok: true, id: crypto.randomUUID() });
  }

  const email = validateEmail(parsed.email);
  if (!email) return jsonResponse(400, { error: "invalid_email" });

  const target = validateTarget(parsed.target);
  if (!target) return jsonResponse(400, { error: "invalid_target" });

  const id = crypto.randomUUID();
  const userAgent = req.headers.get("user-agent");
  const referer = req.headers.get("referer");

  await env.DB.prepare(
    `INSERT INTO scan_requests (id, email, target, ip_hash, user_agent, referer, created_at, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')`,
  )
    .bind(id, email, target, ipHash, userAgent, referer, now)
    .run();

  if (env.DISCORD_WEBHOOK_URL) {
    const payload = buildScanRequestEmbed({
      id,
      email,
      target,
      timestamp: new Date(now).toISOString(),
    });
    ctx.waitUntil(postDiscordWebhook(env.DISCORD_WEBHOOK_URL, payload));
  }

  return jsonResponse(202, { ok: true, id });
}
