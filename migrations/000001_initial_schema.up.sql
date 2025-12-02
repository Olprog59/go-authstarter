-- Initial schema for GoAuthStarter
-- Consolidated migration including all tables, indexes, triggers, and seed data

-- =============================================================================
-- USERS TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL CHECK (
    email <> ''
    AND email LIKE '%@%.%'
    AND LENGTH(email) <= 255
  ),
  password TEXT NOT NULL CHECK (LENGTH(password) <= 128),

  -- Email verification
  email_verified BOOLEAN NOT NULL DEFAULT 0,
  verification_token TEXT CHECK (
    verification_token IS NULL
    OR LENGTH(verification_token) <= 255
  ),
  verification_expires_at TIMESTAMP,

  -- Password reset
  password_reset_token TEXT CHECK (LENGTH(password_reset_token) <= 255),
  password_reset_expires_at TIMESTAMP,

  -- Account lockout (brute force protection)
  failed_login_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TIMESTAMP NULL,

  -- RBAC
  role TEXT NOT NULL DEFAULT 'user',

  -- BaseModel fields
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  deleted_at TIMESTAMP DEFAULT NULL
);

-- =============================================================================
-- REFRESH TOKENS TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS refresh_tokens (
  token TEXT PRIMARY KEY CHECK (LENGTH(token) <= 255),
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  issue_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL CHECK (expires_at > issue_at),
  is_revoked BOOLEAN NOT NULL DEFAULT 0,
  ip_hash TEXT NOT NULL DEFAULT '',
  ua_hash TEXT NOT NULL DEFAULT ''
);

-- =============================================================================
-- PERMISSIONS SYSTEM TABLES
-- =============================================================================
CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS role_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT NOT NULL,
    permission TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(role, permission),
    FOREIGN KEY (permission) REFERENCES permissions(name) ON DELETE CASCADE
);

-- =============================================================================
-- TRIGGERS
-- =============================================================================
-- Auto-update updated_at on users table
CREATE TRIGGER IF NOT EXISTS update_users_timestamp
AFTER UPDATE ON users
FOR EACH ROW
WHEN OLD.updated_at = NEW.updated_at
BEGIN
  UPDATE users
  SET updated_at = CURRENT_TIMESTAMP
  WHERE id = OLD.id;
END;

-- Validate user role on insert
CREATE TRIGGER validate_user_role_insert
BEFORE INSERT ON users
FOR EACH ROW
WHEN NEW.role NOT IN ('user', 'admin', 'moderator')
BEGIN
    SELECT RAISE(ABORT, 'Invalid role. Must be one of: user, admin, moderator');
END;

-- Validate user role on update
CREATE TRIGGER validate_user_role_update
BEFORE UPDATE OF role ON users
FOR EACH ROW
WHEN NEW.role NOT IN ('user', 'admin', 'moderator')
BEGIN
    SELECT RAISE(ABORT, 'Invalid role. Must be one of: user, admin, moderator');
END;

-- =============================================================================
-- INDEXES - USERS TABLE
-- =============================================================================
-- Soft delete index
CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at);

-- Authentication and lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Email verification flow (partial index for non-NULL tokens)
CREATE INDEX IF NOT EXISTS idx_users_verification_token
ON users(verification_token)
WHERE verification_token IS NOT NULL;

-- Password reset flow (partial index for non-NULL tokens)
CREATE INDEX IF NOT EXISTS idx_users_password_reset_token
ON users(password_reset_token)
WHERE password_reset_token IS NOT NULL;

-- Account lockout queries
CREATE INDEX IF NOT EXISTS idx_users_locked_until
ON users(locked_until)
WHERE locked_until IS NOT NULL;

-- RBAC lookups
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- =============================================================================
-- INDEXES - REFRESH TOKENS TABLE
-- =============================================================================
-- Fast token lookup during refresh
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);

-- User tokens lookup
CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);

-- Expiration cleanup
CREATE INDEX IF NOT EXISTS idx_refresh_expires ON refresh_tokens(expires_at);

-- Active tokens queries (composite index)
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_active
ON refresh_tokens(is_revoked, expires_at);

-- =============================================================================
-- INDEXES - PERMISSIONS TABLES
-- =============================================================================
CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission ON role_permissions(permission);

-- =============================================================================
-- SEED DATA - PERMISSIONS
-- =============================================================================
INSERT INTO permissions (name, description) VALUES
    ('users:read', 'Read user information'),
    ('users:write', 'Create or update users'),
    ('users:delete', 'Delete users'),
    ('users:list', 'List all users'),
    ('roles:read', 'Read role information'),
    ('roles:write', 'Assign or change user roles'),
    ('stats:read', 'View system statistics'),
    ('system:admin', 'Full administrative access');

-- =============================================================================
-- SEED DATA - ROLE PERMISSIONS
-- =============================================================================
-- User role: no special permissions (basic access only)

-- Moderator role: can view users and stats
INSERT INTO role_permissions (role, permission) VALUES
    ('moderator', 'users:read'),
    ('moderator', 'users:list'),
    ('moderator', 'stats:read');

-- Admin role: all permissions
INSERT INTO role_permissions (role, permission) VALUES
    ('admin', 'users:read'),
    ('admin', 'users:write'),
    ('admin', 'users:delete'),
    ('admin', 'users:list'),
    ('admin', 'roles:read'),
    ('admin', 'roles:write'),
    ('admin', 'stats:read'),
    ('admin', 'system:admin');
