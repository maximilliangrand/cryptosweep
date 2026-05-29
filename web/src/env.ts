export interface Env {
  DB: D1Database;
  RL_KV: KVNamespace;
  IP_HASH_SECRET: string;
  NODE_ENV: string;
}
