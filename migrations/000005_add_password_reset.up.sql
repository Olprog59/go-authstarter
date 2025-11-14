-- Add password reset functionality to users table
-- This allows users to reset their password via email with a time-limited token

ALTER TABLE users ADD COLUMN password_reset_token TEXT CHECK (LENGTH(password_reset_token) <= 255);
ALTER TABLE users ADD COLUMN password_reset_expires_at TIMESTAMP;

-- Create index for faster token lookups during password reset
CREATE INDEX idx_users_password_reset_token ON users(password_reset_token) WHERE password_reset_token IS NOT NULL;
