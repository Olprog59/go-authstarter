package service

import (
	"context"
	"errors"
	"log/slog"

	"github.com/Olprog59/go-authstarter/internal/config"
	"github.com/Olprog59/go-authstarter/internal/domain"
	"github.com/Olprog59/go-authstarter/internal/ports"
	"github.com/Olprog59/go-authstarter/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// Common service errors
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

// UserService handles user management operations / Gère les opérations de gestion des utilisateurs
type UserService struct {
	reader       ports.UserReader
	writer       ports.UserWriter
	roleRepo     ports.RoleRepository
	refreshStore ports.RefreshTokenStore
	conf         *config.Config
}

// UserMetricsRecorder records user metrics / Enregistre les métriques utilisateur
type UserMetricsRecorder interface {
	RecordRegistration()
}

// NewUserService creates user management service instance / Crée une instance de service de gestion utilisateur
func NewUserService(
	repo ports.UserRepository,
	refreshStore ports.RefreshTokenStore,
	conf *config.Config,
) *UserService {
	return &UserService{
		reader:       repo,
		writer:       repo,
		roleRepo:     repo,
		refreshStore: refreshStore,
		conf:         conf,
	}
}

// Register creates a new user account / Crée un nouveau compte utilisateur
func (s *UserService) Register(ctx context.Context, email, password string) (*domain.User, error) {
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

	// Create user in database with context propagation / Crée l'utilisateur avec propagation du contexte
	createdUser, err := s.writer.Create(ctx, email, string(hashedPassword))
	if err != nil {
		// Check for duplicate email using typed error / Vérifie l'email dupliqué avec erreur typée
		if errors.Is(err, repository.ErrDup) {
			return nil, errors.New("email already registered")
		}
		slog.Error("failed to create user", "err", err)
		return nil, errors.New("failed to create user account")
	}

	return createdUser, nil
}

// GetUser retrieves a user by their ID / Récupère un utilisateur par son ID
func (s *UserService) GetUser(ctx context.Context, id int64) (*domain.User, error) {
	user, err := s.reader.GetByID(ctx, id)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// ListUsers retrieves paginated users / Récupère les utilisateurs paginés
func (s *UserService) ListUsers(ctx context.Context, offset, limit int) ([]*domain.User, int, error) {
	users, totalCount, err := s.reader.List(ctx, offset, limit)
	if err != nil {
		slog.Error("failed to list users", "err", err, "offset", offset, "limit", limit)
		return nil, 0, errors.New("failed to retrieve users")
	}
	return users, totalCount, nil
}

// DeleteUser permanently removes a user / Supprime définitivement un utilisateur
func (s *UserService) DeleteUser(ctx context.Context, userID int64) error {
	// Check if user exists
	_, err := s.reader.GetByID(ctx, userID)
	if err != nil {
		return ErrUserNotFound
	}

	// Revoke all refresh tokens before deletion
	if err := s.refreshStore.RevokeAllForUser(ctx, userID); err != nil {
		slog.Error("failed to revoke tokens during user deletion", "user_id", userID, "err", err)
		// Continue with deletion even if token revocation fails
	}

	// Delete user from database
	if err := s.writer.Delete(ctx, userID); err != nil {
		slog.Error("failed to delete user", "user_id", userID, "err", err)
		return errors.New("failed to delete user")
	}

	return nil
}

// UpdateUserRole changes a user's role / Change le rôle d'un utilisateur
func (s *UserService) UpdateUserRole(ctx context.Context, userID int64, newRole domain.UserRole) error {
	// Validate role
	if !newRole.IsValid() {
		return errors.New("invalid role")
	}

	// Check if user exists
	_, err := s.reader.GetByID(ctx, userID)
	if err != nil {
		return ErrUserNotFound
	}

	// Update role in database
	if err := s.roleRepo.UpdateRole(ctx, userID, string(newRole)); err != nil {
		slog.Error("failed to update user role", "user_id", userID, "new_role", newRole, "err", err)
		return errors.New("failed to update user role")
	}

	return nil
}
