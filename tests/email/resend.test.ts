import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { sendEmail } from "../../src/email/resend";

const INPUT = {
  apiKey: "re_test_123",
  from: "scan@cryptosweep.com",
  to: "lead@example.com",
  subject: "subj",
  html: "<p>hi</p>",
  text: "hi",
};

describe("sendEmail", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("POSTs to the Resend endpoint with the documented shape on success", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ id: "msg_abc" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );

    const result = await sendEmail(INPUT);

    expect(result).toEqual({ id: "msg_abc" });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.mock.calls[0] ?? [];
    expect(url).toBe("https://api.resend.com/emails");
    expect(init?.method).toBe("POST");
    const headers = init?.headers as Record<string, string>;
    expect(headers.authorization).toBe("Bearer re_test_123");
    expect(headers["content-type"]).toBe("application/json");
    const body = JSON.parse(String(init?.body)) as {
      from: string;
      to: string[];
      subject: string;
      html: string;
      text: string;
    };
    expect(body).toEqual({
      from: INPUT.from,
      to: [INPUT.to],
      subject: INPUT.subject,
      html: INPUT.html,
      text: INPUT.text,
    });
  });

  it("returns the error message when Resend responds with a 4xx", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ message: "Invalid API key", name: "validation_error" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      }),
    );

    const result = await sendEmail(INPUT);
    expect(result.id).toBeUndefined();
    expect(result.error).toBe("Invalid API key");
  });

  it("returns an error when fetch rejects (network failure)", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("ECONNRESET"));
    const result = await sendEmail(INPUT);
    expect(result.id).toBeUndefined();
    expect(result.error).toBe("ECONNRESET");
  });

  it("flags a 2xx response that omits an id", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("{}", { status: 200, headers: { "content-type": "application/json" } }),
    );
    const result = await sendEmail(INPUT);
    expect(result.error).toBe("Resend response missing id");
  });
});
