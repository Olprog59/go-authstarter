package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"time"

	"github.com/Olprog59/go-authstarter/internal/ports"
	"github.com/Olprog59/go-authstarter/internal/domain"
)

var _ ports.RefreshTokenStore = (*refreshTokenStore)(nil)

// refreshTokenStore implements RefreshTokenStore / Implémente RefreshTokenStore
type refreshTokenStore struct {
	db ports.DBTX
}

// NewRefreshTokenStore creates token store / Crée le magasin de tokens
func NewRefreshTokenStore(db *sql.DB) ports.RefreshTokenStore {
	return &refreshTokenStore{db: db}
}

// WithTx returns store with transaction / Retourne le magasin avec transaction
func (s *refreshTokenStore) WithTx(tx *sql.Tx) ports.RefreshTokenStore {
	return &refreshTokenStore{db: tx}
}

// Save stores hashed refresh token / Stocke le token haché
func (s *refreshTokenStore) Save(ctx context.Context, t *domain.RefreshToken) error {
	if t == nil {
		return errors.New("the refresh token is null")
	}

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

// Get retrieves refresh token by value / Récupère le token par valeur
func (s *refreshTokenStore) Get(ctx context.Context, tokenString string) (*domain.RefreshToken, error) {
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

// Revoke marks token as revoked / Marque le token comme révoqué
func (s *refreshTokenStore) Revoke(ctx context.Context, tokenString string) error {
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

// RevokeAllForUser revokes all user tokens / Révoque tous les tokens de l'utilisateur
func (s *refreshTokenStore) RevokeAllForUser(ctx context.Context, userID int64) error {
	const query = `
    UPDATE refresh_tokens
    SET is_revoked = 1
    WHERE user_id = ?
    `
	_, err := s.db.ExecContext(ctx, query, userID)
	return err
}

// PurgeExpired deletes expired tokens / Supprime les tokens expirés
func (s *refreshTokenStore) PurgeExpired(ctx context.Context, before time.Time) error {
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
