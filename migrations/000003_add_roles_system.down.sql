-- Drop triggers first
DROP TRIGGER IF EXISTS validate_user_role_update;
DROP TRIGGER IF EXISTS validate_user_role_insert;

-- Drop index
DROP INDEX IF EXISTS idx_users_role;

-- Remove role column (SQLite requires recreating table for column removal)
-- For simplicity, we'll create a backup and recreate the table

-- Create temporary table without role column
CREATE TABLE users_backup (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified BOOLEAN DEFAULT FALSE,
    verification_token TEXT,
    verification_token_expires_at TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP
);

-- Copy data to backup table
INSERT INTO users_backup (id, username, password, created_at, verified, verification_token, verification_token_expires_at, failed_login_attempts, locked_until)
SELECT id, username, password, created_at, verified, verification_token, verification_token_expires_at, failed_login_attempts, locked_until
FROM users;

-- Drop original table
DROP TABLE users;

-- Rename backup table
ALTER TABLE users_backup RENAME TO users;

-- Recreate indexes
CREATE INDEX idx_users_verification_token ON users(verification_token);
CREATE INDEX idx_users_locked_until ON users(locked_until);
