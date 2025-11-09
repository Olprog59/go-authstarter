-- Initial schema for the application
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL CHECK (
    email <> ''
    AND email LIKE '%@%.%'
    AND LENGTH(email) <= 255
  ),
  password TEXT NOT NULL CHECK (LENGTH(password) <= 128),
  email_verified BOOLEAN NOT NULL DEFAULT 0,
  verification_token TEXT CHECK (
    verification_token IS NULL
    OR LENGTH(verification_token) <= 255
  ),
  verification_expires_at TIMESTAMP,

-- BaseModel fields
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  deleted_at TIMESTAMP DEFAULT NULL
);

-- Trigger auto-update updated_at sur users uniquement
CREATE TRIGGER IF NOT EXISTS update_users_timestamp
AFTER UPDATE ON users
FOR EACH ROW
WHEN OLD.updated_at = NEW.updated_at
BEGIN
  UPDATE users
  SET updated_at = CURRENT_TIMESTAMP
  WHERE id = OLD.id;
end
;

CREATE TABLE IF NOT EXISTS refresh_tokens (
  token TEXT PRIMARY KEY CHECK (LENGTH(token) <= 255),
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  issue_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL CHECK (expires_at > issue_at),
  is_revoked BOOLEAN NOT NULL DEFAULT 0,
  ip_hash TEXT NOT NULL DEFAULT '',
  ua_hash TEXT NOT NULL DEFAULT ''
);

-- Index
CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at);
CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_expires ON refresh_tokens(expires_at);

