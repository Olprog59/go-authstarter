package service

import (
	"errors"
	"log/slog"

	"github.com/Olprog59/go-fun/internal/config"
	"github.com/Olprog59/go-fun/internal/domain"
	"github.com/Olprog59/go-fun/internal/ports"
	"golang.org/x/crypto/bcrypt"
)

// Common service errors
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

// UserService handles user management operations (CRUD).
// It follows the Single Responsibility Principle by focusing solely on
// user data management, while authentication, verification, and password
// operations are handled by dedicated services.
type UserService struct {
	repo         ports.UserRepository
	refreshStore ports.RefreshTokenStore
	conf         *config.Config
}

// UserMetricsRecorder defines the interface for recording user-related metrics.
type UserMetricsRecorder interface {
	RecordRegistration()
}

// NewUserService creates a new user management service instance.
func NewUserService(
	repo ports.UserRepository,
	refreshStore ports.RefreshTokenStore,
	conf *config.Config,
) *UserService {
	return &UserService{
		repo:         repo,
		refreshStore: refreshStore,
		conf:         conf,
	}
}

// Register creates a new user account with the provided email and password.
// The registration process includes:
//   - Email format validation
//   - Password strength validation
//   - Password hashing using bcrypt
//   - User creation in database
//
// Note: Email verification is handled separately by VerificationService.
//
// Parameters:
//   - email: User's email address
//   - password: Plain-text password
//
// Returns:
//   - Created user object and error (if any)
func (s *UserService) Register(email, password string) (*domain.User, error) {
	// Validate email format
	if !isValidEmail(email) {
		return nil, errors.New("invalid email format")
	}

	// Validate password strength
	if !isStrongPassword(password) {
		return nil, errors.New("password does not meet strength requirements: must be at least 8 characters with uppercase, lowercase, digit, and special character")
	}

	// Hash password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), s.conf.Security.BcryptCost)
	if err != nil {
		slog.Error("failed to hash password during registration", "err", err)
		return nil, errors.New("failed to process password")
	}

	// Create user in database
	createdUser, err := s.repo.Create(email, string(hashedPassword))
	if err != nil {
		// Check for duplicate email (wrapped by repository)
		if err.Error() == "email already registered" {
			return nil, errors.New("email already registered")
		}
		slog.Error("failed to create user", "err", err)
		return nil, errors.New("failed to create user account")
	}

	return createdUser, nil
}

// GetUser retrieves a user by their ID.
//
// Parameters:
//   - id: User's unique identifier
//
// Returns:
//   - User object and error (if not found)
func (s *UserService) GetUser(id int64) (*domain.User, error) {
	user, err := s.repo.GetByID(id)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// ListUsers retrieves all users from the database.
// This is typically used for admin dashboards and user management interfaces.
//
// Note: In production, consider adding pagination for better performance
// with large user bases.
//
// Returns:
//   - Slice of user objects and error (if any)
func (s *UserService) ListUsers() ([]*domain.User, error) {
	users, err := s.repo.List()
	if err != nil {
		slog.Error("failed to list users", "err", err)
		return nil, errors.New("failed to retrieve users")
	}
	return users, nil
}

// DeleteUser permanently removes a user from the system.
// This operation also:
//   - Revokes all refresh tokens
//   - Removes all associated data
//
// Parameters:
//   - userID: ID of the user to delete
//
// Returns:
//   - Error if user not found or deletion fails
func (s *UserService) DeleteUser(userID int64) error {
	// Check if user exists
	_, err := s.repo.GetByID(userID)
	if err != nil {
		return ErrUserNotFound
	}

	// Revoke all refresh tokens before deletion
	if err := s.refreshStore.RevokeAllForUser(userID); err != nil {
		slog.Error("failed to revoke tokens during user deletion", "user_id", userID, "err", err)
		// Continue with deletion even if token revocation fails
	}

	// Delete user from database
	if err := s.repo.Delete(userID); err != nil {
		slog.Error("failed to delete user", "user_id", userID, "err", err)
		return errors.New("failed to delete user")
	}

	return nil
}

// UpdateUserRole changes a user's role (user, moderator, admin).
// This is a privileged operation that should be protected by authorization middleware.
//
// Parameters:
//   - userID: ID of the user to update
//   - newRole: The new role to assign
//
// Returns:
//   - Error if user not found or update fails
func (s *UserService) UpdateUserRole(userID int64, newRole domain.UserRole) error {
	// Validate role
	if !newRole.IsValid() {
		return errors.New("invalid role")
	}

	// Check if user exists
	_, err := s.repo.GetByID(userID)
	if err != nil {
		return ErrUserNotFound
	}

	// Update role in database
	if err := s.repo.UpdateRole(userID, string(newRole)); err != nil {
		slog.Error("failed to update user role", "user_id", userID, "new_role", newRole, "err", err)
		return errors.New("failed to update user role")
	}

	return nil
}
