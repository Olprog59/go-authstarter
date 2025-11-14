package ports

import (
	"time"

	"github.com/Olprog59/go-fun/internal/domain"
)

// UserRepository defines the contract for user persistence operations.
// This is a "port" in the Hexagonal Architecture, abstracting the underlying
// data storage mechanism for user data. Any concrete implementation (e.g.,
// SQLite, PostgreSQL) must satisfy this interface.
type UserRepository interface {
	// Create inserts a new user record into the persistence layer.
	// It takes the user's email and hashed password, and returns the newly created
	// `domain.User` object with its assigned ID, or an error if the creation fails.
	Create(email, password string) (*domain.User, error)
	// GetByID retrieves a single user record by their unique identifier.
	// It returns the `domain.User` object if found, or an error (e.g., `ErrNotFound`) if not.
	GetByID(id int64) (*domain.User, error)
	// GetByEmail retrieves a single user record by their email address.
	// It returns the `domain.User` object if found, or an error (e.g., `ErrNotFound`) if not.
	GetByEmail(email string) (*domain.User, error)
	// UpdateDBSendEmail updates a user's verification token and its expiration time in the database.
	// This is typically called when a verification email is sent or re-sent.
	UpdateDBSendEmail(token string, expiresAt time.Time, id int64) error
	// UpdateDBVerify marks a user's email as verified and clears their verification token details.
	// This is called after a user successfully verifies their email address.
	UpdateDBVerify(token string) error
	// List retrieves all user records from the persistence layer.
	// It returns a slice of `domain.User` objects, or an error if the retrieval fails.
	List() ([]*domain.User, error)
	// Delete removes a user record from the persistence layer by their unique identifier.
	// It returns an error if the deletion fails.
	Delete(id int64) error
	// IncrementFailedAttempts increments the failed login attempts counter for a user.
	// This is used for brute force protection by tracking failed login attempts.
	IncrementFailedAttempts(userID int64) error
	// ResetFailedAttempts resets the failed login attempts counter to zero for a user.
	// This is typically called after a successful login.
	ResetFailedAttempts(userID int64) error
	// LockAccount locks a user account until a specific timestamp.
	// This prevents the user from logging in until the lock expires.
	LockAccount(userID int64, until time.Time) error
	// UpdateRole changes the role of a user in the system.
	// This is an administrative function used for managing user permissions.
	UpdateRole(userID int64, role string) error
	// CountUsers returns the total number of users in the system.
	// This is used for admin bootstrapping (first user = admin).
	CountUsers() (int, error)

	// GetPermissionsForRole retrieves all permissions assigned to a specific role.
	// Returns a slice of permission strings (e.g., ["users:read", "users:list"]).
	GetPermissionsForRole(role string) ([]domain.Permission, error)

	// UserHasPermission checks if a user has a specific permission based on their role.
	// Returns true if the user's role has the given permission, false otherwise.
	UserHasPermission(userID int64, permission domain.Permission) (bool, error)

	// AddPermissionToRole assigns a permission to a role.
	// This is used for dynamic permission management.
	AddPermissionToRole(role string, permission domain.Permission) error

	// RemovePermissionFromRole removes a permission from a role.
	// This is used for dynamic permission management.
	RemovePermissionFromRole(role string, permission domain.Permission) error

	// SetPasswordResetToken stores a password reset token and its expiration for a user.
	// This is called when a user requests a password reset.
	SetPasswordResetToken(email string, token string, expiresAt time.Time) error

	// GetByPasswordResetToken retrieves a user by their password reset token.
	// Returns the user if the token exists and hasn't expired, or an error otherwise.
	GetByPasswordResetToken(token string) (*domain.User, error)

	// UpdatePassword updates a user's password hash.
	// This is called after successful password reset or password change.
	UpdatePassword(userID int64, hashedPassword string) error

	// ClearPasswordResetToken clears the password reset token and expiration for a user.
	// This is called after a successful password reset to invalidate the token.
	ClearPasswordResetToken(userID int64) error
}
