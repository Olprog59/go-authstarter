-- Revert initial schema
DROP INDEX IF EXISTS idx_refresh_expires;
DROP INDEX IF EXISTS idx_refresh_user;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS users;
