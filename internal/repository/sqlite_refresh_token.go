package repository

import (
	"database/sql"
	"errors"
	"time"

	"github.com/Olprog59/go-fun/internal/domain"
	"github.com/Olprog59/go-fun/internal/ports"
)

var _ ports.RefreshTokenStore = (*SQLiteRefreshTokenStore)(nil)

type SQLiteRefreshTokenStore struct {
	DB *sql.DB
}

func NewSQLiteRefreshTokenStore(db *sql.DB) *SQLiteRefreshTokenStore {
	return &SQLiteRefreshTokenStore{DB: db}
}

func (s *SQLiteRefreshTokenStore) Save(t *domain.RefreshToken) error {
	if t == nil {
		return errors.New("the refrestoken is null")
	}
	const query = `
    INSERT INTO refresh_tokens(token, user_id, issue_at, expires_at, is_revoked)
    VALUES (?, ?, ?, ?, ?)
    `
	_, err := s.DB.Exec(
		query,
		t.Token,
		t.UserID,
		t.IssueAt,
		t.ExpiresAt,
		t.IsRevoked,
	)
	return err
}

func (s *SQLiteRefreshTokenStore) Get(tokenString string) (*domain.RefreshToken, error) {
	const query = `
    SELECT token, user_id, issue_at, expires_at, is_revoked
    FROM refresh_tokens
    WHERE token = ?
    `
	row := s.DB.QueryRow(query, tokenString)

	var t domain.RefreshToken
	if err := row.Scan(
		&t.Token,
		&t.UserID,
		&t.IssueAt,
		&t.ExpiresAt,
		&t.IsRevoked,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, ports.ErrNotFound
		}
		return nil, err
	}
	return &t, nil
}

func (s *SQLiteRefreshTokenStore) Revoke(tokenString string) error {
	const query = `
    UPDATE refresh_tokens
    SET is_revoked = 1
    WHERE token = ?
    `
	_, err := s.DB.Exec(query, tokenString)
	return err
}

func (s *SQLiteRefreshTokenStore) RevokeAllForUser(userID int64) error {
	const query = `
    UPDATE refresh_tokens
    SET is_revoked = 1
    WHERE user_id = ?
    `
	_, err := s.DB.Exec(query, userID)
	return err
}

func (s *SQLiteRefreshTokenStore) PurgeExpired(before time.Time) error {
	const query = `
    DELETE FROM refresh_tokens
    WHERE expires_at < ?
    `
	_, err := s.DB.Exec(query, before)
	return err
}
