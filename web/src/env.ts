export interface Env {
  DB: D1Database;
  RL_KV: KVNamespace;
  RATE_LIMITER: DurableObjectNamespace;
  IP_HASH_SECRET: string;
  NODE_ENV: string;
  DISCORD_WEBHOOK_URL: string;
}
