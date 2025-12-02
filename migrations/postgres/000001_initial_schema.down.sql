-- Rollback initial schema for GoAuthStarter - PostgreSQL

-- Drop triggers
DROP TRIGGER IF EXISTS update_users_updated_at ON users;

-- Drop function
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop tables in reverse order to respect foreign key constraints
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS users;
