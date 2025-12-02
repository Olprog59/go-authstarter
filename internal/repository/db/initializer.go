package db

import (
	"database/sql"
	"fmt"
	"log"
)

// DatabaseConfig holds database connection config / Contient la config de connexion BD
type DatabaseConfig struct {
	Type         DatabaseType
	DSN          string
	MaxOpenConns int
	MaxIdleConns int
}

// DatabaseInitializer initializes database connections / Initialise les connexions BD
type DatabaseInitializer interface {
	Initialize(config DatabaseConfig) (*sql.DB, error)
	ConfigureConnection(db *sql.DB, config DatabaseConfig) error
	Type() DatabaseType
}

// InitializerRegistry manages database initializers / Gère les initialiseurs de BD
type InitializerRegistry[T DatabaseInitializer] struct {
	factories map[DatabaseType]func() T
}

// NewInitializerRegistry creates registry / Crée le registre
func NewInitializerRegistry[T DatabaseInitializer]() *InitializerRegistry[T] {
	return &InitializerRegistry[T]{
		factories: make(map[DatabaseType]func() T),
	}
}

// Register registers initializer factory / Enregistre une factory d'initialiseur
func (r *InitializerRegistry[T]) Register(dbType DatabaseType, factory func() T) {
	r.factories[dbType] = factory
}

// Get retrieves initializer / Récupère l'initialiseur
func (r *InitializerRegistry[T]) Get(dbType DatabaseType, fallback func() T) T {
	if factory, exists := r.factories[dbType]; exists {
		return factory()
	}
	return fallback()
}

// initializerRegistry manages database initializers / Gère les initialiseurs
var initializerRegistry = func() *InitializerRegistry[DatabaseInitializer] {
	registry := NewInitializerRegistry[DatabaseInitializer]()
	registry.Register(MySQL, func() DatabaseInitializer { return &mysqlInitializer{} })
	registry.Register(PostgreSQL, func() DatabaseInitializer { return &postgresInitializer{} })
	registry.Register(SQLite, func() DatabaseInitializer { return &sqliteInitializer{} })
	return registry
}()

// NewDatabaseInitializer creates initializer for database type / Crée l'initialiseur pour le type de BD
func NewDatabaseInitializer(dbType DatabaseType) DatabaseInitializer {
	return initializerRegistry.Get(dbType, func() DatabaseInitializer { return &sqliteInitializer{} })
}

// baseInitializer provides common functionality / Fournit les fonctionnalités communes
type baseInitializer struct{}

func (b *baseInitializer) setConnectionPool(db *sql.DB, config DatabaseConfig) {
	maxOpen := config.MaxOpenConns
	if maxOpen == 0 {
		maxOpen = 25
	}
	maxIdle := config.MaxIdleConns
	if maxIdle == 0 {
		maxIdle = 5
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
}

// MySQL initializer / Initialiseur MySQL
type mysqlInitializer struct {
	baseInitializer
}

func (i *mysqlInitializer) Initialize(config DatabaseConfig) (*sql.DB, error) {
	db, err := sql.Open("mysql", config.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to open mysql connection: %w", err)
	}

	if err := i.ConfigureConnection(db, config); err != nil {
		db.Close()
		return nil, err
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping mysql: %w", err)
	}

	log.Println("MySQL database connected successfully")
	return db, nil
}

func (i *mysqlInitializer) ConfigureConnection(db *sql.DB, config DatabaseConfig) error {
	i.setConnectionPool(db, config)

	// MySQL-specific configuration via session variables
	_, err := db.Exec("SET SESSION sql_mode='TRADITIONAL,NO_AUTO_VALUE_ON_ZERO'")
	if err != nil {
		log.Printf("Warning: failed to set MySQL sql_mode: %v", err)
	}

	return nil
}

func (i *mysqlInitializer) Type() DatabaseType {
	return MySQL
}

// PostgreSQL initializer / Initialiseur PostgreSQL
type postgresInitializer struct {
	baseInitializer
}

func (i *postgresInitializer) Initialize(config DatabaseConfig) (*sql.DB, error) {
	db, err := sql.Open("postgres", config.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres connection: %w", err)
	}

	if err := i.ConfigureConnection(db, config); err != nil {
		db.Close()
		return nil, err
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping postgres: %w", err)
	}

	log.Println("PostgreSQL database connected successfully")
	return db, nil
}

func (i *postgresInitializer) ConfigureConnection(db *sql.DB, config DatabaseConfig) error {
	i.setConnectionPool(db, config)

	// PostgreSQL-specific configuration
	_, err := db.Exec("SET TIME ZONE 'UTC'")
	if err != nil {
		log.Printf("Warning: failed to set PostgreSQL timezone: %v", err)
	}

	return nil
}

func (i *postgresInitializer) Type() DatabaseType {
	return PostgreSQL
}

// SQLite initializer / Initialiseur SQLite
type sqliteInitializer struct {
	baseInitializer
}

func (i *sqliteInitializer) Initialize(config DatabaseConfig) (*sql.DB, error) {
	db, err := sql.Open("sqlite", config.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite connection: %w", err)
	}

	if err := i.ConfigureConnection(db, config); err != nil {
		db.Close()
		return nil, err
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping sqlite: %w", err)
	}

	log.Println("SQLite database connected successfully")
	return db, nil
}

func (i *sqliteInitializer) ConfigureConnection(db *sql.DB, config DatabaseConfig) error {
	i.setConnectionPool(db, config)

	// SQLite-specific PRAGMAs for performance and security
	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA automatic_index=true;",
		"PRAGMA foreign_keys=ON;",
		"PRAGMA analysis_limit=1000;",
		"PRAGMA trusted_schema=OFF;",
		"PRAGMA wal_autocheckpoint=1000;",
		"PRAGMA cache_size=10000;",
	}

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			log.Printf("Warning: failed to execute pragma (%s): %v", pragma, err)
		}
	}

	return nil
}

func (i *sqliteInitializer) Type() DatabaseType {
	return SQLite
}
