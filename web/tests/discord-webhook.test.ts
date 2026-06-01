import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildScanRequestEmbed, postDiscordWebhook } from "../src/lib/discord-webhook";

const WEBHOOK = "https://discord.com/api/webhooks/test/abc";

describe("postDiscordWebhook", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("POSTs the payload as JSON when the URL is set", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(null, { status: 204 }));

    const payload = buildScanRequestEmbed({
      id: "11111111-1111-1111-1111-111111111111",
      email: "lead@example.com",
      target: "example.com",
      timestamp: "2026-05-30T12:00:00.000Z",
    });

    await postDiscordWebhook(WEBHOOK, payload);

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.mock.calls[0] ?? [];
    expect(url).toBe(WEBHOOK);
    expect(init?.method).toBe("POST");
    const headers = init?.headers as Record<string, string>;
    expect(headers["content-type"]).toBe("application/json");
    const body = JSON.parse(String(init?.body)) as {
      content: string;
      embeds: { fields: { name: string; value: string }[]; timestamp: string }[];
    };
    expect(body.content).toBe("🔍 New scan request");
    expect(body.embeds).toHaveLength(1);
    const fields = body.embeds[0]?.fields ?? [];
    expect(fields).toEqual([
      { name: "Email", value: "lead@example.com", inline: true },
      { name: "Target", value: "example.com", inline: true },
      { name: "ID", value: "11111111-1111-1111-1111-111111111111", inline: false },
    ]);
    expect(body.embeds[0]?.timestamp).toBe("2026-05-30T12:00:00.000Z");
  });

  it("returns immediately and never calls fetch when the URL is empty", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    await postDiscordWebhook("", { content: "noop" });
    await postDiscordWebhook(undefined, { content: "noop" });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("swallows fetch errors and does not throw", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("ENETDOWN"));
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    await expect(postDiscordWebhook(WEBHOOK, { content: "x" })).resolves.toBeUndefined();
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("ENETDOWN"));
  });

  it("logs a warning on non-2xx responses without throwing", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("rate limited", { status: 429 }));
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    await expect(postDiscordWebhook(WEBHOOK, { content: "x" })).resolves.toBeUndefined();
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("429"));
  });
});
