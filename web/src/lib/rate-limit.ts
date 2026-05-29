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

interface CounterState {
  count: number;
  resetAt: number;
}

export async function checkRateLimit(
  kv: KVNamespace,
  key: string,
  now: number,
  config: RateLimitConfig = DEFAULT_RATE_LIMIT,
): Promise<RateLimitResult> {
  const nsKey = `rl:${key}`;
  const raw = await kv.get(nsKey);
  let state: CounterState;
  if (raw) {
    try {
      const parsed = JSON.parse(raw) as CounterState;
      state =
        parsed.resetAt > now
          ? parsed
          : { count: 0, resetAt: now + config.windowSeconds * 1000 };
    } catch {
      state = { count: 0, resetAt: now + config.windowSeconds * 1000 };
    }
  } else {
    state = { count: 0, resetAt: now + config.windowSeconds * 1000 };
  }

  if (state.count >= config.limit) {
    return {
      ok: false,
      remaining: 0,
      resetSeconds: Math.max(0, Math.ceil((state.resetAt - now) / 1000)),
    };
  }

  state.count += 1;
  const ttlSeconds = Math.max(1, Math.ceil((state.resetAt - now) / 1000));
  await kv.put(nsKey, JSON.stringify(state), { expirationTtl: ttlSeconds });

  return {
    ok: true,
    remaining: Math.max(0, config.limit - state.count),
    resetSeconds: ttlSeconds,
  };
}
