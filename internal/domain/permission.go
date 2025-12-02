package domain

// Permission represents granular permission (resource:action pattern) / Permission granulaire (pattern resource:action)
type Permission string

// Predefined permissions / Permissions prédéfinies
const (
	PermissionUsersRead    Permission = "users:read"
	PermissionUsersWrite   Permission = "users:write"
	PermissionUsersDelete  Permission = "users:delete"
	PermissionUsersList    Permission = "users:list"
	PermissionRolesRead    Permission = "roles:read"
	PermissionRolesWrite   Permission = "roles:write"
	PermissionStatsRead    Permission = "stats:read"
	PermissionSystemAdmin  Permission = "system:admin"
)

// AllPermissions returns all defined permissions / Retourne toutes les permissions définies
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

// String returns permission as string / Retourne la permission en string
func (p Permission) String() string {
	return string(p)
}

// DefaultPermissionsForRole returns default permissions for role / Retourne les permissions par défaut du rôle
func DefaultPermissionsForRole(role UserRole) []Permission {
	switch role {
	case RoleUser:
		return []Permission{} // No special permissions / Aucune permission spéciale

	case RoleModerator:
		return []Permission{
			PermissionUsersRead,
			PermissionUsersList,
			PermissionStatsRead,
		}

	case RoleAdmin:
		return AllPermissions() // Full system access / Accès complet au système

	default:
		return []Permission{}
	}
}

// RolePermissionModel represents role-permission relationship / Représente la relation rôle-permission
type RolePermissionModel struct {
	ID         int64  `db:"id"`
	Role       string `db:"role"`
	Permission string `db:"permission"`
	CreatedAt  string `db:"created_at"`
}
