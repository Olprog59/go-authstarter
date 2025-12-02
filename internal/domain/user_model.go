package domain

import (
	"database/sql"
	"time"
)

// UserRole represents user's role for authorization / Représente le rôle utilisateur pour l'autorisation
type UserRole string

const (
	RoleUser      UserRole = "user"      // Default role for new users / Rôle par défaut pour nouveaux utilisateurs
	RoleModerator UserRole = "moderator" // Moderator with elevated permissions / Modérateur avec permissions élevées
	RoleAdmin     UserRole = "admin"     // Full admin access / Accès administrateur complet
)

// IsValid checks if role is valid / Vérifie si le rôle est valide
func (r UserRole) IsValid() bool {
	return r == RoleUser || r == RoleModerator || r == RoleAdmin
}

// User represents domain user entity / Représente l'entité utilisateur du domaine
type User struct {
	BaseModel
	ID                     int64
	Email                  string
	Password               string     // Hashed password / Mot de passe haché
	Role                   UserRole
	CreatedAt              time.Time
	Token                  *RefreshToken
	EmailVerified          bool
	VerificationToken      string
	VerificationExpiresAt  time.Time
	FailedLoginAttempts    int        // Failed login counter / Compteur d'échecs de connexion
	LockedUntil            *time.Time // Account lock expiry / Expiration du verrouillage du compte
	PasswordResetToken     sql.NullString
	PasswordResetExpiresAt sql.NullTime
}

// IsLocked checks if account is locked / Vérifie si le compte est verrouillé
func (u *User) IsLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.LockedUntil)
}

// HasRole checks exact role match / Vérifie la correspondance exacte du rôle
func (u *User) HasRole(role UserRole) bool {
	return u.Role == role
}

// IsAdmin checks admin privileges / Vérifie les privilèges admin
func (u *User) IsAdmin() bool {
	return u.Role == RoleAdmin
}

// IsModerator checks moderator privileges / Vérifie les privilèges modérateur
func (u *User) IsModerator() bool {
	return u.Role == RoleModerator
}

// HasMinimumRole checks role hierarchy (admin > moderator > user) / Vérifie la hiérarchie des rôles
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

// RefreshToken represents refresh token entity / Représente l'entité refresh token
type RefreshToken struct {
	Token     string    // Hashed token value / Valeur du token hachée
	UserID    int64
	IssueAt   time.Time
	ExpiresAt time.Time
	IsRevoked bool
	IPHash    string // SHA-256 hash of client IP / Hash SHA-256 de l'IP client
	UAHash    string // SHA-256 hash of User-Agent / Hash SHA-256 du User-Agent
}

// IsTokenExpired checks if token expired / Vérifie si le token est expiré
func (rt *RefreshToken) IsTokenExpired() bool {
	return time.Now().After(rt.ExpiresAt)
}

// IsTokenValid checks if token is valid / Vérifie si le token est valide
func (rt *RefreshToken) IsTokenValid() bool {
	return !rt.IsRevoked && !rt.IsTokenExpired()
}

// IsDeleted checks if soft-deleted / Vérifie si supprimé (soft delete)
func (bm *BaseModel) IsDeleted() bool {
	return bm.DeletedAt != nil
}
