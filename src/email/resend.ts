/**
 * Minimal Resend email client. Wraps POST https://api.resend.com/emails with
 * the global fetch — no SDK dependency.
 */

const RESEND_ENDPOINT = "https://api.resend.com/emails";

export interface SendEmailInput {
  apiKey: string;
  from: string;
  to: string;
  subject: string;
  html: string;
  text: string;
}

export interface SendEmailResult {
  id?: string;
  error?: string;
}

interface ResendOkBody {
  id: string;
}

interface ResendErrorBody {
  message?: string;
  name?: string;
  error?: string;
}

export async function sendEmail(input: SendEmailInput): Promise<SendEmailResult> {
  let response: Response;
  try {
    response = await fetch(RESEND_ENDPOINT, {
      method: "POST",
      headers: {
        authorization: `Bearer ${input.apiKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        from: input.from,
        to: [input.to],
        subject: input.subject,
        html: input.html,
        text: input.text,
      }),
    });
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }

  const raw = await response.text();
  const parsed = parseBody(raw);

  if (!response.ok) {
    const message = (parsed && (parsed.message || parsed.error || parsed.name)) || `Resend HTTP ${response.status}`;
    return { error: message };
  }
  const ok = parsed as ResendOkBody | null;
  if (!ok?.id) return { error: "Resend response missing id" };
  return { id: ok.id };
}

function parseBody(raw: string): (ResendOkBody & ResendErrorBody) | null {
  if (!raw) return null;
  try {
    return JSON.parse(raw) as ResendOkBody & ResendErrorBody;
  } catch {
    return null;
  }
}
