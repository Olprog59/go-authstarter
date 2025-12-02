package ports

import (
	"context"
	"time"

	"github.com/Olprog59/go-fun/internal/common"
	"github.com/Olprog59/go-fun/internal/domain"
)

// UserReader defines the contract for reading user data.
// This interface follows the Interface Segregation Principle by providing
// only read operations. Services that only need to read user data should
// depend on this interface instead of the full UserRepository.
type UserReader interface {
	// GetByID retrieves a single user record by their unique identifier.
	GetByID(ctx context.Context, id int64) (*domain.User, error)

	// GetByEmail retrieves a single user record by their email address.
	GetByEmail(ctx context.Context, email string) (*domain.User, error)

	// List retrieves paginated user records.
	// Parameters:
	//   - ctx: Context for cancellation and timeout control
	//   - offset: Number of records to skip
	//   - limit: Maximum number of records to return
	// Returns: users slice, total count, error
	List(ctx context.Context, offset, limit int) ([]*domain.User, int, error)

	// CountUsers returns the total number of users in the system.
	// Used for admin bootstrapping (first user = admin).
	CountUsers(ctx context.Context) (int, error)
}

// UserWriter defines the contract for creating and deleting users.
// Separated from UserReader to allow services that only need write operations
// to depend on a smaller interface.
type UserWriter interface {
	// Create inserts a new user with email and hashed password.
	// Returns the newly created user with assigned ID.
	Create(ctx context.Context, email, password string) (*domain.User, error)

	// Delete removes a user record by their unique identifier.
	Delete(ctx context.Context, id int64) error
}

// EmailVerificationRepository defines the contract for email verification operations.
// This interface handles the persistence layer for email verification tokens.
type EmailVerificationRepository interface {
	// UpdateDBSendEmail updates a user's verification token and expiration.
	// Called when a verification email is sent or re-sent.
	UpdateDBSendEmail(ctx context.Context, token string, expiresAt time.Time, id int64) error

	// UpdateDBVerify marks a user's email as verified and clears verification token.
	// Called after successful email verification.
	UpdateDBVerify(ctx context.Context, token string) error
}

// AccountSecurityRepository defines the contract for account security operations.
// This interface handles brute force protection through login attempt tracking
// and account lockouts.
type AccountSecurityRepository interface {
	// IncrementFailedAttempts increments the failed login attempts counter.
	// Used for brute force protection.
	IncrementFailedAttempts(ctx context.Context, userID int64) error

	// ResetFailedAttempts resets the failed login attempts counter to zero.
	// Typically called after a successful login.
	ResetFailedAttempts(ctx context.Context, userID int64) error

	// LockAccount locks a user account until a specific timestamp.
	// Prevents login until the lock expires.
	LockAccount(ctx context.Context, userID int64, until time.Time) error

	// WithTx returns a new instance of AccountSecurityRepository that executes operations
	// within the provided common.DBTX (either *sql.DB or *sql.Tx).
	// This is crucial for ensuring transactional consistency across multiple repository calls.
	WithTx(dbtx common.DBTX) AccountSecurityRepository
}

// RoleRepository defines the contract for user role management.
// Separated from permission management to allow for simpler role-only operations.
type RoleRepository interface {
	// UpdateRole changes the role of a user in the system.
	// Administrative function for managing user permissions.
	UpdateRole(ctx context.Context, userID int64, role string) error
}

// PermissionRepository defines the contract for permission management operations.
// This interface handles the granular permission system (RBAC).
type PermissionRepository interface {
	// GetPermissionsForRole retrieves all permissions for a specific role.
	// Returns slice of permissions (e.g., ["users:read", "users:list"]).
	GetPermissionsForRole(ctx context.Context, role string) ([]domain.Permission, error)

	// UserHasPermission checks if a user has a specific permission via their role.
	UserHasPermission(ctx context.Context, userID int64, permission domain.Permission) (bool, error)

	// AddPermissionToRole assigns a permission to a role.
	// Used for dynamic permission management.
	AddPermissionToRole(ctx context.Context, role string, permission domain.Permission) error

	// RemovePermissionFromRole removes a permission from a role.
	// Used for dynamic permission management.
	RemovePermissionFromRole(ctx context.Context, role string, permission domain.Permission) error
}

// PasswordResetRepository defines the contract for password reset operations.
// This interface handles the persistence layer for password reset tokens and
// password updates.
type PasswordResetRepository interface {
	// SetPasswordResetToken stores a password reset token and expiration.
	// Called when a user requests a password reset.
	SetPasswordResetToken(ctx context.Context, email string, token string, expiresAt time.Time) error

	// GetByPasswordResetToken retrieves a user by their password reset token.
	// Returns the user if token exists and hasn't expired.
	GetByPasswordResetToken(ctx context.Context, token string) (*domain.User, error)

	// UpdatePassword updates a user's password hash.
	// Called after successful password reset or password change.
	UpdatePassword(ctx context.Context, userID int64, hashedPassword string) error

	// ClearPasswordResetToken clears the password reset token and expiration.
	// Called after successful password reset to invalidate the token.
	ClearPasswordResetToken(ctx context.Context, userID int64) error
}

// UserRepository is a composite interface that includes all user-related operations.
// DEPRECATED: New services should depend on the specific interfaces they need
// (UserReader, UserWriter, etc.) instead of this monolithic interface.
// This is kept for backward compatibility during the migration phase.
type UserRepository interface {
	UserReader
	UserWriter
	EmailVerificationRepository
	AccountSecurityRepository
	RoleRepository
	PermissionRepository
	PasswordResetRepository
}
