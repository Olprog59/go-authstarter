package ports

import (
	"database/sql"
	"errors"
	"time"

	"github.com/Olprog59/go-fun/internal/domain"
)

var ErrNotFound = errors.New("not found")

type RefreshTokenStore interface {
	Save(token *domain.RefreshToken) error
	Get(tokenString string) (*domain.RefreshToken, error)
	Revoke(tokenString string) error
	RevokeAllForUser(userID int64) error
	PurgeExpired(before time.Time) error
	WithTx(tx *sql.Tx) RefreshTokenStore
}
