-- Rollback account lockout mechanism
-- This removes the columns and index added for brute force protection

DROP INDEX IF EXISTS idx_users_locked_until;
ALTER TABLE users DROP COLUMN locked_until;
ALTER TABLE users DROP COLUMN failed_login_attempts;
