-- DROP TABLE IF EXISTS refresh_tokens;
-- DROP TABLE IF EXISTS users;
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL CHECK (
    email <> ''
    AND email LIKE '%@%.%'
  ),
  password TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  email_verified BOOLEAN NOT NULL DEFAULT 0,
  verification_token TEXT,
  verification_expires_at TIMESTAMP,
  -- Pour éviter les injections SQL par exemple en limitant les tailles maximales
  -- raisonnables
  CHECK (LENGTH(email) <= 255),
  CHECK (LENGTH(password) <= 128),
  CHECK (verification_token IS NULL OR LENGTH(verification_token) <= 255)
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  issue_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  is_revoked BOOLEAN NOT NULL DEFAULT 0,
  ip_hash TEXT NOT NULL DEFAULT '',
  ua_hash TEXT NOT NULL DEFAULT '',
  CHECK (expires_at > issue_at),
  -- Limiter la taille du token pour protection
  CHECK (LENGTH(token) <= 255)
);

CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_expires ON refresh_tokens(expires_at);

