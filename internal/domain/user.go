package domain

import "time"

// User représente l'entité métier User (pure, sans dépendances)
type User struct {
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
