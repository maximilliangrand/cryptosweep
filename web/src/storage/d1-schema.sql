CREATE TABLE IF NOT EXISTS scan_requests (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL,
  target        TEXT NOT NULL,
  ip_hash       TEXT NOT NULL,
  user_agent    TEXT,
  referer       TEXT,
  created_at    INTEGER NOT NULL,
  status        TEXT NOT NULL DEFAULT 'pending'
);
CREATE INDEX IF NOT EXISTS idx_scan_requests_status ON scan_requests(status);
CREATE INDEX IF NOT EXISTS idx_scan_requests_created ON scan_requests(created_at);
