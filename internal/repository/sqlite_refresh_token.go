package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"time"

	"github.com/Olprog59/go-fun/internal/common"
	"github.com/Olprog59/go-fun/internal/domain"
	"github.com/Olprog59/go-fun/internal/ports"
)

var _ ports.RefreshTokenStore = (*sqliteRefreshTokenStore)(nil) // Interface compliance / Vérification d'interface

// sqliteRefreshTokenStore implements RefreshTokenStore for SQLite / Implémente RefreshTokenStore pour SQLite
type sqliteRefreshTokenStore struct {
	db common.DBTX // Database connection or transaction / Connexion BD ou transaction
}

// NewSQLiteRefreshTokenStore creates SQLite token store / Crée le store de tokens SQLite
func NewSQLiteRefreshTokenStore(db *sql.DB) ports.RefreshTokenStore {
	return &sqliteRefreshTokenStore{db: db}
}

// WithTx returns store with transaction support / Retourne le store avec support transactionnel
func (s *sqliteRefreshTokenStore) WithTx(tx *sql.Tx) ports.RefreshTokenStore {
	return &sqliteRefreshTokenStore{db: tx}
}

// Save stores hashed refresh token in database / Stocke le token haché dans la BD
func (s *sqliteRefreshTokenStore) Save(ctx context.Context, t *domain.RefreshToken) error {
	if t == nil {
		return errors.New("the refresh token is null")
	}

	// Store SHA-256 hash, not raw value / Stocke le hash SHA-256, pas la valeur brute
	hashedToken := sha256.Sum256([]byte(t.Token))
	t.Token = hex.EncodeToString(hashedToken[:])

	const query = `
    INSERT INTO refresh_tokens(token, user_id, issue_at, expires_at, is_revoked, ip_hash, ua_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    `
	_, err := s.db.ExecContext(
		ctx,
		query,
		t.Token,
		t.UserID,
		t.IssueAt,
		t.ExpiresAt,
		t.IsRevoked,
		t.IPHash,
		t.UAHash,
	)
	return err
}

// Get retrieves a refresh token from the database by its string value.
// The provided `tokenString` is first hashed using SHA-256 and hex-encoded
// to match the stored hashed value in the database.
//
// Parameters:
//   - tokenString: The raw refresh token string to retrieve.
//
// Returns:
//   - A pointer to the `domain.RefreshToken` object if found.
//   - `ports.ErrNotFound` if no matching token is found.
//   - An error if the database query fails.
func (s *sqliteRefreshTokenStore) Get(ctx context.Context, tokenString string) (*domain.RefreshToken, error) {
	const query = `
    SELECT token, user_id, issue_at, expires_at, is_revoked, ip_hash, ua_hash
    FROM refresh_tokens
    WHERE token = ?
    `
	hashedToken := sha256.Sum256([]byte(tokenString))
	hashed := hex.EncodeToString(hashedToken[:])

	row := s.db.QueryRowContext(ctx, query, hashed)

	var t domain.RefreshToken
	if err := row.Scan(
		&t.Token,
		&t.UserID,
		&t.IssueAt,
		&t.ExpiresAt,
		&t.IsRevoked,
		&t.IPHash,
		&t.UAHash,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ports.ErrNotFound
		}
		return nil, err
	}
	return &t, nil
}

// Revoke marks a specific refresh token as revoked in the database.
// The provided `tokenString` is hashed to find the corresponding record.
// Revoked tokens cannot be used to obtain new access tokens.
//
// Parameters:
//   - tokenString: The raw refresh token string to revoke.
//
// Returns:
//   - An error if the database update operation fails.
func (s *sqliteRefreshTokenStore) Revoke(ctx context.Context, tokenString string) error {
	const query = `
    UPDATE refresh_tokens
    SET is_revoked = 1
    WHERE token = ?
    `
	hashedToken := sha256.Sum256([]byte(tokenString))
	hashed := hex.EncodeToString(hashedToken[:])

	_, err := s.db.ExecContext(ctx, query, hashed)
	return err
}

// RevokeAllForUser revokes all refresh tokens associated with a given user ID.
// This is typically used as a security measure, for example, when a user changes
// their password or logs out from all devices.
//
// Parameters:
//   - userID: The ID of the user whose tokens should be revoked.
//
// Returns:
//   - An error if the database update operation fails.
func (s *sqliteRefreshTokenStore) RevokeAllForUser(ctx context.Context, userID int64) error {
	const query = `
    UPDATE refresh_tokens
    SET is_revoked = 1
    WHERE user_id = ?
    `
	_, err := s.db.ExecContext(ctx, query, userID)
	return err
}

// PurgeExpired deletes all refresh tokens from the database that have expired
// before the specified `before` timestamp. This is a maintenance task to
// keep the database clean and prevent the accumulation of stale tokens.
//
// Parameters:
//   - before: A `time.Time` value; all tokens expiring before this time will be deleted.
//
// Returns:
//   - An error if the database deletion operation fails.
func (s *sqliteRefreshTokenStore) PurgeExpired(ctx context.Context, before time.Time) error {
	const query = `
    DELETE FROM refresh_tokens
    WHERE expires_at < ?
    `
	res, err := s.db.ExecContext(ctx, query, before)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	log.Printf("Purged %d expired refresh token(s)", n)
	return nil
}
