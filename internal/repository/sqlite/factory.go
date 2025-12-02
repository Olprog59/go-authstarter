package sqlite

import (
	"database/sql"

	"github.com/Olprog59/go-authstarter/internal/ports"
)

// Factory implements DatabaseFactory for SQLite / Implémente DatabaseFactory pour SQLite
// The compile-time check is in adapter.go to avoid import cycles
// La vérification à la compilation est dans adapter.go pour éviter les cycles d'imports
type Factory struct{}

// NewUserRepository creates user repository / Crée le repository utilisateur
func (f *Factory) NewUserRepository(db *sql.DB) ports.UserRepository {
	return NewUserRepository(db)
}

// NewRefreshTokenStore creates refresh token store / Crée le store de refresh tokens
func (f *Factory) NewRefreshTokenStore(db *sql.DB) ports.RefreshTokenStore {
	return NewRefreshTokenStore(db)
}
