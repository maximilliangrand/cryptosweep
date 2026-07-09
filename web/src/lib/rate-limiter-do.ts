/**
 * Durable Object rate limiter.
 *
 * The previous KV limiter was a read-modify-write: two concurrent requests could
 * both read count=4 and both write count=5, so the limit was not actually
 * enforced under load. A Durable Object serializes all delivery to a single
 * instance per key, and its input/output gates keep the get-then-put atomic, so
 * the counter is correct even under a burst. One DO instance per client key.
 */
import type { RateLimitConfig, RateLimitResult } from "./rate-limit";
import { DEFAULT_RATE_LIMIT } from "./rate-limit";

interface CounterState {
  count: number;
  resetAt: number;
}

export class RateLimiter {
  private readonly storage: DurableObjectStorage;
  private readonly config: RateLimitConfig;

  constructor(state: DurableObjectState) {
    this.storage = state.storage;
    this.config = DEFAULT_RATE_LIMIT;
  }

  async fetch(): Promise<Response> {
    const now = Date.now();
    const stored = await this.storage.get<CounterState>("state");
    const fresh = !stored || stored.resetAt <= now;
    const state: CounterState = fresh ? { count: 0, resetAt: now + this.config.windowSeconds * 1000 } : stored;

    if (state.count >= this.config.limit) {
      return Response.json({
        ok: false,
        remaining: 0,
        resetSeconds: Math.max(0, Math.ceil((state.resetAt - now) / 1000)),
      } satisfies RateLimitResult);
    }

    state.count += 1;
    await this.storage.put("state", state);
    // Let the key expire once the window closes, so idle clients leave no state.
    await this.storage.setAlarm(state.resetAt);

    return Response.json({
      ok: true,
      remaining: Math.max(0, this.config.limit - state.count),
      resetSeconds: Math.max(1, Math.ceil((state.resetAt - now) / 1000)),
    } satisfies RateLimitResult);
  }

  /** When the window closes, drop the stored counter. */
  async alarm(): Promise<void> {
    await this.storage.deleteAll();
  }
}

/** Atomically consume one unit from the per-key limiter. */
export async function checkRateLimitDurable(
  namespace: DurableObjectNamespace,
  key: string,
): Promise<RateLimitResult> {
  const stub = namespace.get(namespace.idFromName(key));
  const response = await stub.fetch("https://rate-limiter.internal/check");
  return (await response.json()) as RateLimitResult;
}
