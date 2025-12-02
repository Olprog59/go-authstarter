package ports

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Olprog59/go-fun/internal/domain"
)

// ErrNotFound is returned when a requested resource (e.g., a refresh token) is not found.
var ErrNotFound = errors.New("not found")

// RefreshTokenStore defines the interface for managing refresh tokens.
// This is a "port" in the Hexagonal Architecture, abstracting the persistence
// layer for refresh tokens. Any concrete implementation (e.g., SQLite, PostgreSQL)
// must satisfy this interface.
type RefreshTokenStore interface {
	// Save stores a new refresh token in the persistence layer.
	// It takes a pointer to a `domain.RefreshToken` and returns an error if the operation fails.
	Save(ctx context.Context, token *domain.RefreshToken) error
	// Get retrieves a refresh token by its string value.
	// It returns the `domain.RefreshToken` if found, or `ErrNotFound` if not.
	Get(ctx context.Context, tokenString string) (*domain.RefreshToken, error)
	// Revoke marks a specific refresh token as revoked, preventing its future use.
	// It takes the token string and returns an error if the operation fails.
	Revoke(ctx context.Context, tokenString string) error
	// RevokeAllForUser revokes all refresh tokens associated with a given user ID.
	// This is typically used during password changes or when a user logs out from all devices.
	RevokeAllForUser(ctx context.Context, userID int64) error
	// PurgeExpired removes all refresh tokens that have expired before a given time.
	// This is a maintenance operation to keep the token store clean.
	PurgeExpired(ctx context.Context, before time.Time) error
	// WithTx returns a new instance of the RefreshTokenStore that operates within
	// the provided SQL transaction. This allows multiple repository operations
	// to be part of a single atomic database transaction.
	WithTx(tx *sql.Tx) RefreshTokenStore
}
