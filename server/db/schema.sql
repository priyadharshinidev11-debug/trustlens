-- TrustLens schema. Written to run unchanged on PostgreSQL and SQLite:
-- ids are UUID strings made by the app, timestamps are ISO-8601 text, JSON is stored as text.

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
  created_at    TEXT NOT NULL,
  last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS scans (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind       TEXT NOT NULL,
  input      TEXT NOT NULL,
  verdict    TEXT NOT NULL,
  score      INTEGER NOT NULL,
  result     TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_user_created ON scans (user_id, created_at);

CREATE TABLE IF NOT EXISTS reports (
  id          TEXT PRIMARY KEY,
  user_id     TEXT REFERENCES users(id) ON DELETE SET NULL,
  kind        TEXT NOT NULL CHECK (kind IN ('url', 'upi', 'phone', 'message')),
  value       TEXT NOT NULL,
  category    TEXT NOT NULL,
  description TEXT,
  status      TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'rejected')),
  confirms    INTEGER NOT NULL DEFAULT 0,
  disputes    INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_lookup ON reports (kind, value);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports (status, created_at);

CREATE TABLE IF NOT EXISTS report_votes (
  report_id  TEXT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  vote       INTEGER NOT NULL CHECK (vote IN (1, -1)),
  created_at TEXT NOT NULL,
  PRIMARY KEY (report_id, user_id)
);

CREATE TABLE IF NOT EXISTS api_keys (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  prefix       TEXT NOT NULL,
  key_hash     TEXT NOT NULL UNIQUE,
  created_at   TEXT NOT NULL,
  last_used_at TEXT,
  revoked      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys (user_id);
