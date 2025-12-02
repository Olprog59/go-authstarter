-- Rollback initial schema
-- Drops all tables, indexes, and triggers in reverse order

-- =============================================================================
-- DROP TRIGGERS
-- =============================================================================
DROP TRIGGER IF EXISTS validate_user_role_update;
DROP TRIGGER IF EXISTS validate_user_role_insert;
DROP TRIGGER IF EXISTS update_users_timestamp;

-- =============================================================================
-- DROP INDEXES - PERMISSIONS TABLES
-- =============================================================================
DROP INDEX IF EXISTS idx_role_permissions_permission;
DROP INDEX IF EXISTS idx_role_permissions_role;

-- =============================================================================
-- DROP INDEXES - REFRESH TOKENS TABLE
-- =============================================================================
DROP INDEX IF EXISTS idx_refresh_tokens_active;
DROP INDEX IF EXISTS idx_refresh_expires;
DROP INDEX IF EXISTS idx_refresh_user;
DROP INDEX IF EXISTS idx_refresh_tokens_token;

-- =============================================================================
-- DROP INDEXES - USERS TABLE
-- =============================================================================
DROP INDEX IF EXISTS idx_users_role;
DROP INDEX IF EXISTS idx_users_locked_until;
DROP INDEX IF EXISTS idx_users_password_reset_token;
DROP INDEX IF EXISTS idx_users_verification_token;
DROP INDEX IF EXISTS idx_users_email;
DROP INDEX IF EXISTS idx_users_deleted_at;

-- =============================================================================
-- DROP TABLES (in order respecting foreign key constraints)
-- =============================================================================
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS users;
