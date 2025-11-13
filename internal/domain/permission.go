package domain

// Permission represents a granular permission in the system.
// Permissions follow the "resource:action" pattern (e.g., "users:read", "users:write").
type Permission string

// Predefined permissions for the application.
// These follow the pattern: resource:action
const (
	// User management permissions
	PermissionUsersRead   Permission = "users:read"   // Read user information
	PermissionUsersWrite  Permission = "users:write"  // Create or update users
	PermissionUsersDelete Permission = "users:delete" // Delete users
	PermissionUsersList   Permission = "users:list"   // List all users

	// Role management permissions
	PermissionRolesRead  Permission = "roles:read"  // Read role information
	PermissionRolesWrite Permission = "roles:write" // Assign or change user roles

	// Statistics and reporting permissions
	PermissionStatsRead Permission = "stats:read" // View system statistics

	// System-level permissions
	PermissionSystemAdmin Permission = "system:admin" // Full administrative access
)

// AllPermissions returns a slice of all defined permissions in the system.
// This is useful for seeding the database or validating permissions.
func AllPermissions() []Permission {
	return []Permission{
		PermissionUsersRead,
		PermissionUsersWrite,
		PermissionUsersDelete,
		PermissionUsersList,
		PermissionRolesRead,
		PermissionRolesWrite,
		PermissionStatsRead,
		PermissionSystemAdmin,
	}
}

// String returns the string representation of the permission.
func (p Permission) String() string {
	return string(p)
}

// DefaultPermissionsForRole returns the default permissions assigned to each role.
// This defines the permission hierarchy:
// - user: No special permissions (basic authenticated access)
// - moderator: Can read users, list users, and view stats
// - admin: All permissions (full system access)
func DefaultPermissionsForRole(role UserRole) []Permission {
	switch role {
	case RoleUser:
		// Regular users have no administrative permissions
		// They can only access their own resources via ownership checks
		return []Permission{}

	case RoleModerator:
		// Moderators can view user information and statistics
		return []Permission{
			PermissionUsersRead,
			PermissionUsersList,
			PermissionStatsRead,
		}

	case RoleAdmin:
		// Admins have full access to all system resources
		return AllPermissions()

	default:
		return []Permission{}
	}
}

// RolePermissionModel represents the many-to-many relationship between roles and permissions.
// This is the database model for the role_permissions junction table.
type RolePermissionModel struct {
	ID         int64      `db:"id"`
	Role       string     `db:"role"`       // Role name (user, moderator, admin)
	Permission string     `db:"permission"` // Permission string (e.g., "users:read")
	CreatedAt  string     `db:"created_at"` // ISO8601 timestamp
}
