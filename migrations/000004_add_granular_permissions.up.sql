-- Create permissions table
-- Stores all available permissions in the system
CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,           -- Permission name (e.g., "users:read")
    description TEXT NOT NULL,            -- Human-readable description
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create role_permissions junction table
-- Maps which permissions are assigned to which roles (many-to-many relationship)
CREATE TABLE IF NOT EXISTS role_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT NOT NULL,                   -- Role name (user, moderator, admin)
    permission TEXT NOT NULL,             -- Permission name (e.g., "users:read")
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Ensure a role can't have the same permission twice
    UNIQUE(role, permission),

    -- Foreign key to permissions table
    FOREIGN KEY (permission) REFERENCES permissions(name) ON DELETE CASCADE
);

-- Create indexes for efficient permission lookups
CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission ON role_permissions(permission);

-- Seed all available permissions
INSERT INTO permissions (name, description) VALUES
    ('users:read', 'Read user information'),
    ('users:write', 'Create or update users'),
    ('users:delete', 'Delete users'),
    ('users:list', 'List all users'),
    ('roles:read', 'Read role information'),
    ('roles:write', 'Assign or change user roles'),
    ('stats:read', 'View system statistics'),
    ('system:admin', 'Full administrative access');

-- Assign default permissions to roles
-- User role: no special permissions (basic access only)
-- (No rows needed for user role)

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
