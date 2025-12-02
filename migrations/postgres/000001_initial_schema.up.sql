-- Initial schema for GoAuthStarter - PostgreSQL
-- Consolidated migration including all tables, indexes, triggers, and seed data

-- =============================================================================
-- USERS TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL CHECK (
    email <> '' AND
    email LIKE '%@%.%' AND
    LENGTH(email) <= 255
  ),
  password VARCHAR(128) NOT NULL CHECK (LENGTH(password) <= 128),

  -- Email verification
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  verification_token VARCHAR(255) DEFAULT NULL,
  verification_expires_at TIMESTAMP DEFAULT NULL,

  -- Password reset
  password_reset_token VARCHAR(255) DEFAULT NULL,
  password_reset_expires_at TIMESTAMP DEFAULT NULL,

  -- Account lockout (brute force protection)
  failed_login_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TIMESTAMP DEFAULT NULL,

  -- RBAC
  role VARCHAR(50) NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin', 'moderator')),

  -- BaseModel fields
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP DEFAULT NULL
);

-- =============================================================================
-- REFRESH TOKENS TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS refresh_tokens (
  token VARCHAR(255) PRIMARY KEY CHECK (LENGTH(token) <= 255),
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  issue_at TIMESTAMP NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMP NOT NULL CHECK (expires_at > issue_at),
  is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
  ip_hash VARCHAR(255) NOT NULL DEFAULT '',
  ua_hash VARCHAR(255) NOT NULL DEFAULT ''
);

-- =============================================================================
-- PERMISSIONS SYSTEM TABLES
-- =============================================================================
CREATE TABLE IF NOT EXISTS permissions (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS role_permissions (
    id BIGSERIAL PRIMARY KEY,
    role VARCHAR(50) NOT NULL,
    permission VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),

    UNIQUE(role, permission),
    FOREIGN KEY (permission) REFERENCES permissions(name) ON DELETE CASCADE
);

-- =============================================================================
-- TRIGGERS FOR AUTO-UPDATE TIMESTAMP
-- =============================================================================
-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for users table
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- INDEXES - USERS TABLE
-- =============================================================================
CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_verification_token ON users(verification_token) WHERE verification_token IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_password_reset_token ON users(password_reset_token) WHERE password_reset_token IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_locked_until ON users(locked_until) WHERE locked_until IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- =============================================================================
-- INDEXES - REFRESH TOKENS TABLE
-- =============================================================================
CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_expires ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_active ON refresh_tokens(is_revoked, expires_at);

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
