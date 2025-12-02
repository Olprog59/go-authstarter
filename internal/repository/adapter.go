package repository

import (
	"database/sql"
	"strings"

	"github.com/Olprog59/go-authstarter/internal/ports"
	"github.com/Olprog59/go-authstarter/internal/repository/mysql"
	"github.com/Olprog59/go-authstarter/internal/repository/postgres"
	"github.com/Olprog59/go-authstarter/internal/repository/sqlite"
)

// Compile-time checks to ensure all Factory implementations satisfy DatabaseFactory interface
// If a Factory doesn't implement all methods, the code won't compile
// Vérifications à la compilation pour s'assurer que toutes les implémentations de Factory satisfont l'interface DatabaseFactory
// Si une Factory n'implémente pas toutes les méthodes, le code ne compilera pas
var (
	_ DatabaseFactory = (*sqlite.Factory)(nil)
	_ DatabaseFactory = (*mysql.Factory)(nil)
	_ DatabaseFactory = (*postgres.Factory)(nil)
)

// factoryRegistry holds all database factories / Registre de toutes les factories de BD
// No switch statements - just a map lookup / Pas de switch - juste une recherche dans la map
var factoryRegistry = map[string]DatabaseFactory{
	"sqlite":     &sqlite.Factory{},
	"sqlite3":    &sqlite.Factory{},
	"mysql":      &mysql.Factory{},
	"postgres":   &postgres.Factory{},
	"postgresql": &postgres.Factory{},
}

// Adapter adapts database connection to repositories / Adapte la connexion BD vers les repositories
type Adapter struct {
	db      *sql.DB
	factory DatabaseFactory
}

// NewAdapter creates repository adapter / Crée l'adapteur de repositories
func NewAdapter(db *sql.DB, driver string) *Adapter {
	// Lookup factory from registry (no switch needed)
	// Recherche la factory dans le registre (pas de switch nécessaire)
	factory := factoryRegistry[strings.ToLower(driver)]
	if factory == nil {
		factory = &sqlite.Factory{} // default fallback
	}

	return &Adapter{
		db:      db,
		factory: factory,
	}
}

// UserRepository returns appropriate user repository / Retourne le repository utilisateur approprié
func (a *Adapter) UserRepository() ports.UserRepository {
	return a.factory.NewUserRepository(a.db)
}

// RefreshTokenStore returns appropriate refresh token store / Retourne le store de refresh tokens approprié
func (a *Adapter) RefreshTokenStore() ports.RefreshTokenStore {
	return a.factory.NewRefreshTokenStore(a.db)
}
