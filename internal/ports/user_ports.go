package ports

import (
	"context"
	"time"

	"github.com/Olprog59/go-authstarter/internal/domain"
)

// UserReader reads user data / Lit les données utilisateur
type UserReader interface {
	// GetByID retrieves user by unique ID / Récupère l'utilisateur par ID unique
	GetByID(ctx context.Context, id int64) (*domain.User, error)

	// GetByEmail retrieves user by email / Récupère l'utilisateur par email
	GetByEmail(ctx context.Context, email string) (*domain.User, error)

	// List retrieves paginated users / Récupère les utilisateurs paginés
	List(ctx context.Context, offset, limit int) ([]*domain.User, int, error)

	// CountUsers returns total user count / Retourne le nombre total d'utilisateurs
	CountUsers(ctx context.Context) (int, error)
}

// UserWriter creates and deletes users / Crée et supprime les utilisateurs
type UserWriter interface {
	// Create inserts new user / Insère un nouvel utilisateur
	Create(ctx context.Context, email, password string) (*domain.User, error)

	// Delete removes user by ID / Supprime l'utilisateur par ID
	Delete(ctx context.Context, id int64) error
}

// EmailVerificationRepository manages email verification / Gère la vérification des emails
type EmailVerificationRepository interface {
	// UpdateDBSendEmail updates verification token and expiration / Met à jour le token et l'expiration
	UpdateDBSendEmail(ctx context.Context, token string, expiresAt time.Time, id int64) error

	// UpdateDBVerify marks email as verified / Marque l'email comme vérifiée
	UpdateDBVerify(ctx context.Context, token string) error
}

// AccountSecurityRepository manages account security / Gère la sécurité des comptes
type AccountSecurityRepository interface {
	// IncrementFailedAttempts increments failed login counter / Incrémente le compteur d'échecs
	IncrementFailedAttempts(ctx context.Context, userID int64) error

	// ResetFailedAttempts resets failed attempt counter / Réinitialise le compteur d'échecs
	ResetFailedAttempts(ctx context.Context, userID int64) error

	// LockAccount locks account until timestamp / Verrouille le compte jusqu'à l'heure
	LockAccount(ctx context.Context, userID int64, until time.Time) error

	// WithTx returns repository with transaction context / Retourne le référentiel avec transaction
	WithTx(dbtx DBTX) AccountSecurityRepository
}

// RoleRepository manages user roles / Gère les rôles des utilisateurs
type RoleRepository interface {
	// UpdateRole changes user role / Change le rôle de l'utilisateur
	UpdateRole(ctx context.Context, userID int64, role string) error
}

// PermissionRepository manages permissions / Gère les permissions
type PermissionRepository interface {
	// GetPermissionsForRole gets permissions for role / Obtient les permissions du rôle
	GetPermissionsForRole(ctx context.Context, role string) ([]domain.Permission, error)

	// UserHasPermission checks if user has permission / Vérifie si l'utilisateur a la permission
	UserHasPermission(ctx context.Context, userID int64, permission domain.Permission) (bool, error)

	// AddPermissionToRole assigns permission to role / Assigne une permission au rôle
	AddPermissionToRole(ctx context.Context, role string, permission domain.Permission) error

	// RemovePermissionFromRole removes permission from role / Supprime la permission du rôle
	RemovePermissionFromRole(ctx context.Context, role string, permission domain.Permission) error
}

// PasswordResetRepository manages password resets / Gère les réinitialisations de mot de passe
type PasswordResetRepository interface {
	// SetPasswordResetToken stores reset token and expiration / Stocke le token et l'expiration
	SetPasswordResetToken(ctx context.Context, email string, token string, expiresAt time.Time) error

	// GetByPasswordResetToken retrieves user by reset token / Récupère l'utilisateur par token
	GetByPasswordResetToken(ctx context.Context, token string) (*domain.User, error)

	// UpdatePassword updates password hash / Met à jour le hash du mot de passe
	UpdatePassword(ctx context.Context, userID int64, hashedPassword string) error

	// ClearPasswordResetToken clears reset token / Efface le token de réinitialisation
	ClearPasswordResetToken(ctx context.Context, userID int64) error
}

// UserRepository is composite interface for all user operations / Interface composite pour toutes les opérations utilisateur
// DEPRECATED: Prefer specific interfaces instead / Préférez les interfaces spécifiques
type UserRepository interface {
	UserReader
	UserWriter
	EmailVerificationRepository
	AccountSecurityRepository
	RoleRepository
	PermissionRepository
	PasswordResetRepository
}
