package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"time"

	"github.com/Olprog59/go-fun/internal/domain"
	"github.com/Olprog59/go-fun/internal/ports"
)

var _ ports.RefreshTokenStore = (*sqliteRefreshTokenStore)(nil)

type sqliteRefreshTokenStore struct {
	db DBTX
}

func NewSQLiteRefreshTokenStore(db *sql.DB) ports.RefreshTokenStore {
	return &sqliteRefreshTokenStore{db: db}
}

// WithTx returns a new store that operates within the given transaction.
func (s *sqliteRefreshTokenStore) WithTx(tx *sql.Tx) ports.RefreshTokenStore {
	return &sqliteRefreshTokenStore{db: tx}
}

func (s *sqliteRefreshTokenStore) Save(t *domain.RefreshToken) error {
	if t == nil {
		return errors.New("the refrestoken is null")
	}

	hashedToken := sha256.Sum256([]byte(t.Token))
	t.Token = hex.EncodeToString(hashedToken[:])

	const query = `
    INSERT INTO refresh_tokens(token, user_id, issue_at, expires_at, is_revoked)
    VALUES (?, ?, ?, ?, ?)
    `
	_, err := s.db.ExecContext(
		context.Background(),
		query,
		t.Token,
		t.UserID,
		t.IssueAt,
		t.ExpiresAt,
		t.IsRevoked,
	)
	return err
}

func (s *sqliteRefreshTokenStore) Get(tokenString string) (*domain.RefreshToken, error) {
	const query = `
    SELECT token, user_id, issue_at, expires_at, is_revoked
    FROM refresh_tokens
    WHERE token = ?
    `
	hashedToken := sha256.Sum256([]byte(tokenString))
	hashed := hex.EncodeToString(hashedToken[:])

	row := s.db.QueryRowContext(context.Background(), query, hashed)

	var t domain.RefreshToken
	if err := row.Scan(
		&t.Token,
		&t.UserID,
		&t.IssueAt,
		&t.ExpiresAt,
		&t.IsRevoked,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ports.ErrNotFound
		}
		return nil, err
	}
	return &t, nil
}

func (s *sqliteRefreshTokenStore) Revoke(tokenString string) error {
	const query = `
    UPDATE refresh_tokens
    SET is_revoked = 1
    WHERE token = ?
    `
	hashedToken := sha256.Sum256([]byte(tokenString))
	hashed := hex.EncodeToString(hashedToken[:])

	_, err := s.db.ExecContext(context.Background(), query, hashed)
	return err
}

func (s *sqliteRefreshTokenStore) RevokeAllForUser(userID int64) error {
	const query = `
    UPDATE refresh_tokens
    SET is_revoked = 1
    WHERE user_id = ?
    `
	_, err := s.db.ExecContext(context.Background(), query, userID)
	return err
}

func (s *sqliteRefreshTokenStore) PurgeExpired(before time.Time) error {
	const query = `
    DELETE FROM refresh_tokens
    WHERE expires_at < ?
    `
	res, err := s.db.ExecContext(context.Background(), query, before)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	log.Printf("Purged %d expired refresh token(s)", n)
	return nil
}
