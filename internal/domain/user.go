package domain

import "time"

// User représente l'entité métier User (pure, sans dépendances)
type User struct {
	ID        int64
	Email     string
	Password  string
	CreatedAt time.Time
	Token     *RefreshToken
}

// RefreshToken représente un refresh token stocké.
type RefreshToken struct {
	Token     string
	UserID    int64
	IssueAt   time.Time
	ExpiresAt time.Time
	IsRevoked bool
}
