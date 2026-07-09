import landingHtml from "./landing.html";
import { handleScanRequest } from "./api/scan-request";
import type { Env } from "./env";

export { RateLimiter } from "./lib/rate-limiter-do";

const PRIVACY_HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Cryptosweep — Privacy</title>
<style>body{margin:0;font:16px/1.6 ui-sans-serif,system-ui,sans-serif;color:#111;background:#fafaf7}main{max-width:640px;margin:0 auto;padding:48px 24px}h1{font-size:26px}h2{font-size:17px;margin-top:28px}a{color:#0a5}code{background:#eee;padding:1px 5px;border-radius:4px}</style>
</head><body><main>
<h1>Privacy</h1>
<p>The scan-request form collects only what is needed to run the scan you asked for and send you the report.</p>
<h2>What we collect</h2>
<p>Your work email, the domain you asked us to scan, and request metadata (a keyed one-way hash of your IP address — never the raw IP — plus user agent and referrer). We do not use third-party analytics or advertising trackers.</p>
<h2>How we use it</h2>
<p>To generate and email your post-quantum readiness report, to rate-limit abuse, and to contact you about the report. We do not sell your data.</p>
<h2>Retention & contact</h2>
<p>Requests are deleted once fulfilled and on request. Email <a href="mailto:scan@cryptosweep.com">scan@cryptosweep.com</a> to access or delete your data.</p>
<p><a href="/">&larr; Back</a></p>
</main></body></html>`;

const HTML_HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "cache-control": "public, max-age=300",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
};

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);

    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "")) {
      return new Response(landingHtml, { status: 200, headers: HTML_HEADERS });
    }

    if (req.method === "POST" && url.pathname === "/api/scan-request") {
      return handleScanRequest(req, env, ctx);
    }

    if (req.method === "GET" && url.pathname === "/privacy") {
      return new Response(PRIVACY_HTML, { status: 200, headers: HTML_HEADERS });
    }

    if (req.method === "GET" && url.pathname === "/healthz") {
      return new Response("ok", { status: 200, headers: { "content-type": "text/plain" } });
    }

    return new Response("Not found", { status: 404, headers: { "content-type": "text/plain" } });
  },
} satisfies ExportedHandler<Env>;
