-- Rollback password reset functionality

DROP INDEX IF EXISTS idx_users_password_reset_token;

ALTER TABLE users DROP COLUMN password_reset_expires_at;
ALTER TABLE users DROP COLUMN password_reset_token;
