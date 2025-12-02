-- Rollback initial schema for GoAuthStarter - MySQL

-- Drop tables in reverse order to respect foreign key constraints
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS users;
