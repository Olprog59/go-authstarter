package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/Olprog59/go-fun/internal/config"
	"github.com/Olprog59/go-fun/internal/ports"
	"github.com/Olprog59/go-fun/internal/repository"
	"github.com/Olprog59/go-fun/internal/service"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "modernc.org/sqlite"
)

// Container regroupe toutes les dépendances
// Pattern: Dependency Injection Container + Hexagonal Architecture
type Container struct {
	DB *sql.DB

	// Ports (interfaces)
	UserRepo ports.UserRepository

	// Services (business logic)
	UserSvc *service.UserService

	Config            *config.Config
	RefreshTokenStore ports.RefreshTokenStore

	ctxCancel context.CancelFunc
}

func NewContainer(cfg *config.Config) (*Container, error) {
	c := &Container{}
	c.Config = cfg

	if err := c.initDatabase(); err != nil {
		return nil, fmt.Errorf("database init: %w", err)
	}

	if err := c.runMigrations(); err != nil {
		c.Close()
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	c.initRepositories()
	c.initServices()

	return c, nil
}

func (c *Container) initDatabase() error {
	db, err := sql.Open("sqlite", c.Config.Database.DSN)
	if err != nil {
		return err
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)

	exec := func(q string) {
		if _, err := db.Exec(q); err != nil {
			log.Printf("pragma failed (%s): %v", q, err)
		}
	}
	exec("PRAGMA journal_mode=WAL;")
	exec("PRAGMA synchronous=NORMAL;")
	exec("PRAGMA busy_timeout = 5000;")
	exec("PRAGMA automatic_index = true;")
	exec("PRAGMA foreign_keys = ON;")
	exec("PRAGMA analysis_limit = 1000;")
	exec("PRAGMA trusted_schema = OFF;")
	exec("PRAGMA wal_autocheckpoint=1000;")
	exec("PRAGMA cache_size=10000;")

	if err := db.Ping(); err != nil {
		db.Close()
		return err
	}

	c.DB = db
	log.Println("Database connected")
	return nil
}

func (c *Container) runMigrations() error {
	driver, err := sqlite.WithInstance(c.DB, &sqlite.Config{})
	if err != nil {
		return fmt.Errorf("could not create sqlite driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://migrations",
		"sqlite",
		driver,
	)
	if err != nil {
		return fmt.Errorf("could not create migrate instance: %w", err)
	}

	log.Println("Applying database migrations...")
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("an error occurred while migrating: %w", err)
	}

	log.Println("Database migrations applied successfully.")
	return nil
}

func (c *Container) initRepositories() {
	c.UserRepo = repository.NewSQLiteUser(c.DB)
}

func (c *Container) initServices() {
	c.RefreshTokenStore = repository.NewSQLiteRefreshTokenStore(c.DB)
	c.UserSvc = service.NewUserService(c.UserRepo, c.Config, c.RefreshTokenStore, c.DB)

	ctx, cancel := context.WithCancel(context.Background())
	c.ctxCancel = cancel

	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := c.RefreshTokenStore.PurgeExpired(time.Now()); err != nil {
					log.Printf("purge failed: %v", err)
				}
			case <-ctx.Done():
				log.Println("purge goroutine stopped")
				return
			}
		}
	}()
}

// Dans Close(), ajoute :
func (c *Container) Close() error {
	if c.ctxCancel != nil {
		c.ctxCancel()
	}
	if c.DB != nil {
		log.Println("Closing database...")
		return c.DB.Close()
	}
	return nil
}
