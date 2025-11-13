-- Add role column to users table with default 'user' role
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user';

-- Create index on role for faster lookups
CREATE INDEX idx_users_role ON users(role);

-- Update existing users to have 'user' role (defensive, already has default)
UPDATE users SET role = 'user' WHERE role IS NULL OR role = '';

-- Add constraint to ensure only valid roles are used
-- SQLite doesn't support CHECK constraints on ALTER TABLE, so we add it via trigger
CREATE TRIGGER validate_user_role_insert
BEFORE INSERT ON users
FOR EACH ROW
WHEN NEW.role NOT IN ('user', 'admin', 'moderator')
BEGIN
    SELECT RAISE(ABORT, 'Invalid role. Must be one of: user, admin, moderator');
END;

CREATE TRIGGER validate_user_role_update
BEFORE UPDATE OF role ON users
FOR EACH ROW
WHEN NEW.role NOT IN ('user', 'admin', 'moderator')
BEGIN
    SELECT RAISE(ABORT, 'Invalid role. Must be one of: user, admin, moderator');
END;
