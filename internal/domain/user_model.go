package domain

import "time"

// User représente l'entité métier User (pure, sans dépendances)
type User struct {
	BaseModel
	ID                    int64
	Email                 string
	Password              string
	CreatedAt             time.Time
	Token                 *RefreshToken
	EmailVerified         bool
	VerificationToken     string
	VerificationExpiresAt time.Time
}

// RefreshToken représente un refresh token stocké.
type RefreshToken struct {
	Token     string
	UserID    int64
	IssueAt   time.Time
	ExpiresAt time.Time
	IsRevoked bool
	IPHash    string // SHA-256 de l'IP client (net.ParseIP + hash)
	UAHash    string // SHA-256 de l'User-Agent
}

// IsTokenExpired vérifie si le token est expiré
func (rt *RefreshToken) IsTokenExpired() bool {
	return time.Now().After(rt.ExpiresAt)
}

// IsTokenValid vérifie si le token est valide (non révoqué et non expiré)
func (rt *RefreshToken) IsTokenValid() bool {
	return !rt.IsRevoked && !rt.IsTokenExpired()
}

// IsDeleted vérifie si l'entité a été soft-deleted
func (bm *BaseModel) IsDeleted() bool {
	return bm.DeletedAt != nil
}
