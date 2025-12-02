package db

import (
	"database/sql"
	"fmt"

	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
)

// DriverConfig holds driver metadata / Contient les métadonnées du driver
type DriverConfig[T any] struct {
	Name       string
	DBType     DatabaseType
	CreateFunc func(*sql.DB, T) (database.Driver, error)
	Config     T
}

// MigrationDriver creates migration driver using generics / Crée un driver de migration avec génériques
type MigrationDriver[T any] struct {
	config DriverConfig[T]
}

// NewMigrationDriver creates migration driver / Crée un driver de migration
func NewMigrationDriver[T any](config DriverConfig[T]) *MigrationDriver[T] {
	return &MigrationDriver[T]{config: config}
}

// CreateDriver creates database driver / Crée le driver de base de données
func (d *MigrationDriver[T]) CreateDriver(db *sql.DB) (database.Driver, error) {
	return d.config.CreateFunc(db, d.config.Config)
}

// DriverName returns driver name / Retourne le nom du driver
func (d *MigrationDriver[T]) DriverName() string {
	return d.config.Name
}

// Type returns database type / Retourne le type de base de données
func (d *MigrationDriver[T]) Type() DatabaseType {
	return d.config.DBType
}

// MigrationDriverFactory creates migration drivers / Crée les drivers de migration
type MigrationDriverFactory interface {
	CreateDriver(db *sql.DB) (database.Driver, error)
	DriverName() string
	Type() DatabaseType
}

// MigrationDriverRegistry manages migration drivers / Gère les drivers de migration
type MigrationDriverRegistry struct {
	factories map[DatabaseType]MigrationDriverFactory
}

// NewMigrationDriverRegistry creates registry / Crée le registre
func NewMigrationDriverRegistry() *MigrationDriverRegistry {
	registry := &MigrationDriverRegistry{
		factories: make(map[DatabaseType]MigrationDriverFactory),
	}

	registry.Register(SQLite, NewMigrationDriver(DriverConfig[*sqlite.Config]{
		Name:   "sqlite3",
		DBType: SQLite,
		CreateFunc: func(db *sql.DB, cfg *sqlite.Config) (database.Driver, error) {
			return sqlite.WithInstance(db, cfg)
		},
		Config: &sqlite.Config{},
	}))

	registry.Register(MySQL, NewMigrationDriver(DriverConfig[*mysql.Config]{
		Name:   "mysql",
		DBType: MySQL,
		CreateFunc: func(db *sql.DB, cfg *mysql.Config) (database.Driver, error) {
			return mysql.WithInstance(db, cfg)
		},
		Config: &mysql.Config{},
	}))

	registry.Register(PostgreSQL, NewMigrationDriver(DriverConfig[*postgres.Config]{
		Name:   "postgres",
		DBType: PostgreSQL,
		CreateFunc: func(db *sql.DB, cfg *postgres.Config) (database.Driver, error) {
			return postgres.WithInstance(db, cfg)
		},
		Config: &postgres.Config{},
	}))

	return registry
}

// Register adds migration driver factory / Ajoute une factory de migration
func (r *MigrationDriverRegistry) Register(dbType DatabaseType, factory MigrationDriverFactory) {
	r.factories[dbType] = factory
}

// GetFactory retrieves migration driver factory / Récupère la factory de migration
func (r *MigrationDriverRegistry) GetFactory(dbType DatabaseType) (MigrationDriverFactory, error) {
	factory, exists := r.factories[dbType]
	if !exists {
		return nil, fmt.Errorf("unsupported database type for migrations: %s", dbType)
	}
	return factory, nil
}
