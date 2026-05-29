export type ValidationError =
  | "invalid_email"
  | "invalid_target"
  | "invalid_body";

export interface ValidatedRequest {
  email: string;
  target: string;
  honeypot: string;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DOMAIN_RE = /^[a-z0-9.-]+\.[a-z]{2,}$/;

export function validateEmail(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim().toLowerCase();
  if (trimmed.length < 6 || trimmed.length > 254) return null;
  if (!EMAIL_RE.test(trimmed)) return null;
  return trimmed;
}

export function validateTarget(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  if (trimmed.length < 4 || trimmed.length > 253) return null;
  if (!DOMAIN_RE.test(trimmed)) return null;
  return trimmed;
}

export function validateHoneypot(raw: unknown): boolean {
  if (raw === undefined || raw === null) return true;
  return typeof raw === "string" && raw.length === 0;
}

export interface ParsedBody {
  email: unknown;
  target: unknown;
  company_url: unknown;
}

export async function parseBody(req: Request): Promise<ParsedBody | null> {
  const ct = req.headers.get("content-type") ?? "";
  try {
    if (ct.includes("application/json")) {
      const json = (await req.json()) as Record<string, unknown>;
      return {
        email: json["email"],
        target: json["target"],
        company_url: json["company_url"],
      };
    }
    if (ct.includes("application/x-www-form-urlencoded") || ct.includes("multipart/form-data")) {
      const form = await req.formData();
      return {
        email: form.get("email"),
        target: form.get("target"),
        company_url: form.get("company_url"),
      };
    }
  } catch {
    return null;
  }
  return null;
}
