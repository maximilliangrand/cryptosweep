/**
 * Fire-and-forget Discord webhook poster. Never throws to the caller —
 * Discord delivery is best-effort and must not block or fail the request.
 */

export interface DiscordEmbedField {
  name: string;
  value: string;
  inline?: boolean;
}

export interface DiscordEmbed {
  title?: string;
  color?: number;
  fields?: DiscordEmbedField[];
  timestamp?: string;
}

export interface DiscordPayload {
  content?: string;
  embeds?: DiscordEmbed[];
}

export async function postDiscordWebhook(url: string | undefined, payload: DiscordPayload): Promise<void> {
  if (!url) return;
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      // eslint-disable-next-line no-console -- Worker has no logger; this surfaces in `wrangler tail`.
      console.error(`discord-webhook: HTTP ${res.status}`);
    }
  } catch (err) {
    // eslint-disable-next-line no-console -- Worker has no logger; this surfaces in `wrangler tail`.
    console.error(`discord-webhook: ${err instanceof Error ? err.message : String(err)}`);
  }
}

export function buildScanRequestEmbed(input: {
  id: string;
  email: string;
  target: string;
  timestamp: string;
}): DiscordPayload {
  return {
    content: "🔍 New scan request",
    embeds: [
      {
        title: "Cryptosweep scan request",
        color: 5814783,
        fields: [
          { name: "Email", value: input.email, inline: true },
          { name: "Target", value: input.target, inline: true },
          { name: "ID", value: input.id, inline: false },
        ],
        timestamp: input.timestamp,
      },
    ],
  };
}
