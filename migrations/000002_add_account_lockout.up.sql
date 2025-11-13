-- Add fields for account lockout mechanism (brute force protection)
-- This migration adds two new columns to the users table:
--   1. failed_login_attempts: Tracks consecutive failed login attempts
--   2. locked_until: Timestamp until which the account is locked (NULL if not locked)
--
-- Security policy:
--   - After 5 failed attempts, account is locked for 15 minutes
--   - Counter resets on successful login
--   - locked_until is automatically cleared after expiration

ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until TIMESTAMP NULL;

-- Create an index on locked_until for efficient queries checking if accounts are locked
CREATE INDEX idx_users_locked_until ON users(locked_until) WHERE locked_until IS NOT NULL;
