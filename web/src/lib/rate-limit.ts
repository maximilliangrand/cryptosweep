/**
 * Shared rate-limit contract.
 *
 * The enforcement lives in the Durable Object ({@link ./rate-limiter-do}); this
 * module holds only the config and result shapes both sides agree on.
 */
export interface RateLimitConfig {
  limit: number;
  windowSeconds: number;
}

export interface RateLimitResult {
  ok: boolean;
  remaining: number;
  resetSeconds: number;
}

export const DEFAULT_RATE_LIMIT: RateLimitConfig = {
  limit: 5,
  windowSeconds: 60,
};
