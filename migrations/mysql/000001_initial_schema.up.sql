-- Initial schema for GoAuthStarter - MySQL
-- Consolidated migration including all tables, indexes, triggers, and seed data

-- =============================================================================
-- USERS TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS users (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(128) NOT NULL,

  -- Email verification
  email_verified TINYINT(1) NOT NULL DEFAULT 0,
  verification_token VARCHAR(255) DEFAULT NULL,
  verification_expires_at DATETIME DEFAULT NULL,

  -- Password reset
  password_reset_token VARCHAR(255) DEFAULT NULL,
  password_reset_expires_at DATETIME DEFAULT NULL,

  -- Account lockout (brute force protection)
  failed_login_attempts INT NOT NULL DEFAULT 0,
  locked_until DATETIME DEFAULT NULL,

  -- RBAC
  role VARCHAR(50) NOT NULL DEFAULT 'user',

  -- BaseModel fields
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  deleted_at DATETIME DEFAULT NULL,

  -- Constraints
  CONSTRAINT chk_email_format CHECK (
    email <> '' AND
    email LIKE '%@%.%' AND
    LENGTH(email) <= 255
  ),
  CONSTRAINT chk_password_length CHECK (LENGTH(password) <= 128),
  CONSTRAINT chk_role CHECK (role IN ('user', 'admin', 'moderator'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================================================
-- REFRESH TOKENS TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS refresh_tokens (
  token VARCHAR(255) PRIMARY KEY,
  user_id BIGINT NOT NULL,
  issue_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  is_revoked TINYINT(1) NOT NULL DEFAULT 0,
  ip_hash VARCHAR(255) NOT NULL DEFAULT '',
  ua_hash VARCHAR(255) NOT NULL DEFAULT '',

  CONSTRAINT chk_expires_after_issue CHECK (expires_at > issue_at),
  CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id)
    REFERENCES users(id) ON DELETE CASCADE,

  INDEX idx_refresh_user (user_id),
  INDEX idx_refresh_expires (expires_at),
  INDEX idx_refresh_active (is_revoked, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================================================
-- PERMISSIONS SYSTEM TABLES
-- =============================================================================
CREATE TABLE IF NOT EXISTS permissions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS role_permissions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    role VARCHAR(50) NOT NULL,
    permission VARCHAR(100) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY unique_role_permission (role, permission),
    CONSTRAINT fk_role_permissions_permission FOREIGN KEY (permission)
      REFERENCES permissions(name) ON DELETE CASCADE,

    INDEX idx_role_permissions_role (role),
    INDEX idx_role_permissions_permission (permission)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================================================
-- INDEXES - USERS TABLE
-- =============================================================================
CREATE INDEX idx_users_deleted_at ON users(deleted_at);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_verification_token ON users(verification_token);
CREATE INDEX idx_users_password_reset_token ON users(password_reset_token);
CREATE INDEX idx_users_locked_until ON users(locked_until);
CREATE INDEX idx_users_role ON users(role);

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
