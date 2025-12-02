package repository

import (
	"database/sql"

	"github.com/Olprog59/go-authstarter/internal/ports"
	"github.com/Olprog59/go-authstarter/internal/repository/sqlite"
)

// NewSQLiteUser creates SQLite user repository for tests / Crée un repository utilisateur SQLite pour les tests
func NewSQLiteUser(database *sql.DB) ports.UserRepository {
	return sqlite.NewUserRepository(database)
}

// NewSQLiteRefreshTokenStore creates SQLite refresh token store for tests / Crée un store de refresh tokens SQLite pour les tests
func NewSQLiteRefreshTokenStore(database *sql.DB) ports.RefreshTokenStore {
	return sqlite.NewRefreshTokenStore(database)
}
