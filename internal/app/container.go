package app

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Olprog59/go-fun/internal/config"
	"github.com/Olprog59/go-fun/internal/ports"
	"github.com/Olprog59/go-fun/internal/repository"
	"github.com/Olprog59/go-fun/internal/service"
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

	if err := c.migrateFromFile("migrations/001_schema.sql"); err != nil {
		c.Close()
		return nil, fmt.Errorf("migration: %w", err)
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

	// Ajustements perf/sécurité
	exec := func(q string) {
		if _, err := db.Exec(q); err != nil {
			log.Printf("pragma failed (%s): %v", q, err)
		}
	}
	exec("PRAGMA journal_mode=WAL;")
	exec("PRAGMA synchronous=NORMAL;")
	exec("PRAGMA foreign_keys=ON;")
	exec("PRAGMA wal_autocheckpoint=1000;")
	exec("PRAGMA cache_size=10000;") // négatif pour pages, positif pour KB

	if err := db.Ping(); err != nil {
		db.Close()
		return err
	}

	c.DB = db
	log.Println("Database connected")
	return nil
}

func (c *Container) migrateFromFile(path string) error {
	sqlBytes, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// Exécute tout le script d’un coup
	if _, err := c.DB.Exec(string(sqlBytes)); err != nil {
		return err
	}
	log.Println("Migrations from file completed")
	return nil
}

func (c *Container) initRepositories() {
	c.UserRepo = repository.NewSQLiteUser(c.DB)
}

func (c *Container) initServices() {
	c.RefreshTokenStore = repository.NewSQLiteRefreshTokenStore(c.DB)
	c.UserSvc = service.NewUserService(c.UserRepo, c.Config, c.RefreshTokenStore)

	// Purge quotidienne + arrêt propre
	ctx, cancel := context.WithCancel(context.Background())
	c.ctxCancel = cancel // ajoute `ctxCancel context.CancelFunc` dans struct Container

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
