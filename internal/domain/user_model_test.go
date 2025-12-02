package domain

import (
	"testing"
	"time"
)

func TestUserRole_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		role  UserRole
		valid bool
	}{
		{"Valid user role", RoleUser, true},
		{"Valid moderator role", RoleModerator, true},
		{"Valid admin role", RoleAdmin, true},
		{"Invalid role", UserRole("invalid"), false},
		{"Empty role", UserRole(""), false},
		{"Uppercase role", UserRole("USER"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.role.IsValid(); got != tt.valid {
				t.Errorf("IsValid() = %v, want %v for role %q", got, tt.valid, tt.role)
			}
		})
	}
}

func TestUser_IsLocked(t *testing.T) {
	now := time.Now()
	future := now.Add(1 * time.Hour)
	past := now.Add(-1 * time.Hour)

	tests := []struct {
		name        string
		lockedUntil *time.Time
		want        bool
	}{
		{"Not locked (nil)", nil, false},
		{"Locked (future time)", &future, true},
		{"Not locked (past time)", &past, false},
		{"Edge case (now)", &now, false}, // At exact moment, considered unlocked
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &User{LockedUntil: tt.lockedUntil}
			if got := user.IsLocked(); got != tt.want {
				t.Errorf("IsLocked() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUser_HasRole(t *testing.T) {
	tests := []struct {
		name     string
		userRole UserRole
		checkRole UserRole
		want     bool
	}{
		{"User has user role", RoleUser, RoleUser, true},
		{"User doesn't have admin role", RoleUser, RoleAdmin, false},
		{"Admin has admin role", RoleAdmin, RoleAdmin, true},
		{"Admin doesn't have user role (exact match)", RoleAdmin, RoleUser, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &User{Role: tt.userRole}
			if got := user.HasRole(tt.checkRole); got != tt.want {
				t.Errorf("HasRole(%v) = %v, want %v", tt.checkRole, got, tt.want)
			}
		})
	}
}

func TestUser_IsAdmin(t *testing.T) {
	tests := []struct {
		name string
		role UserRole
		want bool
	}{
		{"Admin user", RoleAdmin, true},
		{"Moderator user", RoleModerator, false},
		{"Regular user", RoleUser, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &User{Role: tt.role}
			if got := user.IsAdmin(); got != tt.want {
				t.Errorf("IsAdmin() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUser_IsModerator(t *testing.T) {
	tests := []struct {
		name string
		role UserRole
		want bool
	}{
		{"Moderator user", RoleModerator, true},
		{"Admin user", RoleAdmin, false},
		{"Regular user", RoleUser, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &User{Role: tt.role}
			if got := user.IsModerator(); got != tt.want {
				t.Errorf("IsModerator() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUser_HasMinimumRole(t *testing.T) {
	tests := []struct {
		name         string
		userRole     UserRole
		requiredRole UserRole
		want         bool
	}{
		{"Admin has minimum user role", RoleAdmin, RoleUser, true},
		{"Admin has minimum moderator role", RoleAdmin, RoleModerator, true},
		{"Admin has minimum admin role", RoleAdmin, RoleAdmin, true},
		{"Moderator has minimum user role", RoleModerator, RoleUser, true},
		{"Moderator has minimum moderator role", RoleModerator, RoleModerator, true},
		{"Moderator doesn't have admin role", RoleModerator, RoleAdmin, false},
		{"User has minimum user role", RoleUser, RoleUser, true},
		{"User doesn't have moderator role", RoleUser, RoleModerator, false},
		{"User doesn't have admin role", RoleUser, RoleAdmin, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &User{Role: tt.userRole}
			if got := user.HasMinimumRole(tt.requiredRole); got != tt.want {
				t.Errorf("HasMinimumRole(%v) = %v, want %v", tt.requiredRole, got, tt.want)
			}
		})
	}
}

func TestRefreshToken_IsTokenExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{"Not expired (future)", time.Now().Add(1 * time.Hour), false},
		{"Expired (past)", time.Now().Add(-1 * time.Hour), true},
		{"Just expired", time.Now().Add(-1 * time.Millisecond), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &RefreshToken{ExpiresAt: tt.expiresAt}
			if got := token.IsTokenExpired(); got != tt.want {
				t.Errorf("IsTokenExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRefreshToken_IsTokenValid(t *testing.T) {
	now := time.Now()
	future := now.Add(1 * time.Hour)
	past := now.Add(-1 * time.Hour)

	tests := []struct {
		name      string
		expiresAt time.Time
		isRevoked bool
		want      bool
	}{
		{"Valid token", future, false, true},
		{"Expired token", past, false, false},
		{"Revoked token", future, true, false},
		{"Revoked and expired", past, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &RefreshToken{
				ExpiresAt: tt.expiresAt,
				IsRevoked: tt.isRevoked,
			}
			if got := token.IsTokenValid(); got != tt.want {
				t.Errorf("IsTokenValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBaseModel_IsDeleted(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		deletedAt *time.Time
		want      bool
	}{
		{"Not deleted", nil, false},
		{"Deleted", &now, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bm := &BaseModel{DeletedAt: tt.deletedAt}
			if got := bm.IsDeleted(); got != tt.want {
				t.Errorf("IsDeleted() = %v, want %v", got, tt.want)
			}
		})
	}
}
