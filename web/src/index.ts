import landingHtml from "./landing.html";
import { handleScanRequest } from "./api/scan-request";
import type { Env } from "./env";

const HTML_HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "cache-control": "public, max-age=300",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
};

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "")) {
      return new Response(landingHtml, { status: 200, headers: HTML_HEADERS });
    }

    if (req.method === "POST" && url.pathname === "/api/scan-request") {
      return handleScanRequest(req, env);
    }

    if (req.method === "GET" && url.pathname === "/healthz") {
      return new Response("ok", { status: 200, headers: { "content-type": "text/plain" } });
    }

    return new Response("Not found", { status: 404, headers: { "content-type": "text/plain" } });
  },
} satisfies ExportedHandler<Env>;
