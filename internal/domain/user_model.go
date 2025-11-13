package domain

import "time"

// UserRole represents a user's role in the system.
// Roles are used for authorization and access control throughout the application.
type UserRole string

const (
	// RoleUser is the default role assigned to newly registered users.
	// Users with this role have access to standard user features.
	RoleUser UserRole = "user"

	// RoleModerator is assigned to users who can moderate content and users.
	// Moderators have elevated permissions to manage community content.
	RoleModerator UserRole = "moderator"

	// RoleAdmin is the highest privilege level with full system access.
	// Admins can manage all users, content, and system settings.
	RoleAdmin UserRole = "admin"
)

// IsValid checks if the role is one of the defined valid roles.
func (r UserRole) IsValid() bool {
	return r == RoleUser || r == RoleModerator || r == RoleAdmin
}

// User represents the core business entity for a user.
// This struct is "pure" as it belongs to the domain layer and has no dependencies
// on external packages like databases or serializers. It defines the essential
// properties of a user within the system.
type User struct {
	BaseModel             // Embeds common fields like CreatedAt, UpdatedAt, DeletedAt.
	ID                    int64
	Email                 string     // The user's unique email address.
	Password              string     // The hashed password.
	Role                  UserRole   // The user's role for authorization (user, moderator, admin).
	CreatedAt             time.Time  // Timestamp of when the user was created.
	Token                 *RefreshToken
	EmailVerified         bool       // Flag indicating if the user has verified their email address.
	VerificationToken     string     // The token sent to the user for email verification.
	VerificationExpiresAt time.Time  // The expiration time of the verification token.
	FailedLoginAttempts   int        // Counter for consecutive failed login attempts (for brute force protection).
	LockedUntil           *time.Time // Timestamp until which the account is locked (NULL if not locked).
}

// IsLocked checks if the user account is currently locked due to too many failed login attempts.
// An account is considered locked if LockedUntil is set and the current time is before that timestamp.
// If LockedUntil has passed, the account is no longer locked (even if the field is not cleared yet).
func (u *User) IsLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.LockedUntil)
}

// HasRole checks if the user has the exact specified role.
func (u *User) HasRole(role UserRole) bool {
	return u.Role == role
}

// IsAdmin checks if the user has admin privileges.
func (u *User) IsAdmin() bool {
	return u.Role == RoleAdmin
}

// IsModerator checks if the user has moderator privileges.
func (u *User) IsModerator() bool {
	return u.Role == RoleModerator
}

// HasMinimumRole checks if the user has at least the specified role level.
// Role hierarchy: admin > moderator > user
// For example, an admin HasMinimumRole(RoleUser) returns true.
func (u *User) HasMinimumRole(role UserRole) bool {
	roleHierarchy := map[UserRole]int{
		RoleUser:      1,
		RoleModerator: 2,
		RoleAdmin:     3,
	}

	userLevel := roleHierarchy[u.Role]
	requiredLevel := roleHierarchy[role]

	return userLevel >= requiredLevel
}

// RefreshToken represents a stored refresh token.
// This entity is used to manage user sessions and allows for the issuance of new
// access tokens without requiring the user to re-authenticate.
type RefreshToken struct {
	Token     string    // The refresh token value itself (often stored as a hash).
	UserID    int64     // The ID of the user who owns the token.
	IssueAt   time.Time // The timestamp when the token was issued.
	ExpiresAt time.Time // The timestamp when the token will expire.
	IsRevoked bool      // A flag to indicate if the token has been revoked.
	IPHash    string    // A SHA-256 hash of the client's IP address, used for security binding.
	UAHash    string    // A SHA-256 hash of the client's User-Agent, for security binding.
}

// IsTokenExpired checks if the refresh token has passed its expiration time.
// It compares the current time with the token's `ExpiresAt` timestamp.
func (rt *RefreshToken) IsTokenExpired() bool {
	return time.Now().After(rt.ExpiresAt)
}

// IsTokenValid checks if the refresh token is currently valid.
// A token is considered valid if it has not been revoked AND it has not expired.
// This provides a single, convenient method for checking the overall validity of a token.
func (rt *RefreshToken) IsTokenValid() bool {
	return !rt.IsRevoked && !rt.IsTokenExpired()
}

// IsDeleted checks if the entity has been "soft-deleted".
// Soft deletion is a pattern where a record is marked as deleted (e.g., by setting a
// `DeletedAt` timestamp) instead of being permanently removed from the database.
// This allows for data recovery and maintains historical integrity.
func (bm *BaseModel) IsDeleted() bool {
	return bm.DeletedAt != nil
}
