package ports

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Olprog59/go-authstarter/internal/domain"
)

// ErrNotFound returned when resource not found / Retourné quand la ressource n'est pas trouvée
var ErrNotFound = errors.New("not found")

// RefreshTokenStore manages refresh tokens / Gère les tokens de rafraîchissement
type RefreshTokenStore interface {
	// Save stores refresh token / Stocke le token de rafraîchissement
	Save(ctx context.Context, token *domain.RefreshToken) error
	// Get retrieves refresh token by value / Récupère le token par sa valeur
	Get(ctx context.Context, tokenString string) (*domain.RefreshToken, error)
	// Revoke marks token as revoked / Marque le token comme révoqué
	Revoke(ctx context.Context, tokenString string) error
	// RevokeAllForUser revokes all user tokens / Révoque tous les tokens de l'utilisateur
	RevokeAllForUser(ctx context.Context, userID int64) error
	// PurgeExpired removes expired tokens / Supprime les tokens expirés
	PurgeExpired(ctx context.Context, before time.Time) error
	// WithTx returns repository with transaction / Retourne le référentiel avec transaction
	WithTx(tx *sql.Tx) RefreshTokenStore
}
