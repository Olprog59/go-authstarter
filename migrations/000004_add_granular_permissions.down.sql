-- Drop tables in reverse order (respecting foreign key constraints)
DROP INDEX IF EXISTS idx_role_permissions_permission;
DROP INDEX IF EXISTS idx_role_permissions_role;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
