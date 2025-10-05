package app

import (
	"database/sql"
	"fmt"
	"log"

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
	// ProductRepo ports.ProductRepository
	// OrderRepo ports.OrderRepository

	// Services (business logic)
	UserSvc *service.UserService
	// ProductSvc *service.ProductService
	// OrderSvc *service.OrderService
}

func NewContainer(cfg *config.Config) (*Container, error) {
	c := &Container{}

	if err := c.initDatabase(cfg); err != nil {
		return nil, fmt.Errorf("database init: %w", err)
	}

	if err := c.migrate(); err != nil {
		c.Close()
		return nil, fmt.Errorf("migration: %w", err)
	}

	c.initRepositories(cfg)
	c.initServices(cfg)

	return c, nil
}

func (c *Container) initDatabase(cfg *config.Config) error {
	db, err := sql.Open("sqlite", cfg.DatabaseURL)
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
	exec("PRAGMA synchronous=NORMAL;")
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

func (c *Container) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			token TEXT UNIQUE
		)`,
		`CREATE TABLE IF NOT EXISTS tokens (
				token TEXT PRIMARY KEY,
				user_id INTEGER NOT NULL,
				issued_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				expires_at DATETIME NOT NULL,
				revoked BOOLEAN NOT NULL DEFAULT 0,
				FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		);`,
	}

	for _, migration := range migrations {
		if _, err := c.DB.Exec(migration); err != nil {
			return err
		}
	}

	log.Println("Migrations completed")
	return nil
}

func (c *Container) initRepositories(conf *config.Config) {
	// Injection des implémentations concrètes dans les ports
	c.UserRepo = repository.NewSQLiteUser(c.DB)
	// c.ProductRepo = repository.NewSQLiteProduct(c.DB)
	// c.OrderRepo = repository.NewSQLiteOrder(c.DB)
}

func (c *Container) initServices(conf *config.Config) {
	// Les services dépendent des ports, pas des implémentations
	c.UserSvc = service.NewUserService(c.UserRepo, conf)
	// c.ProductSvc = service.NewProductService(c.ProductRepo)
	// c.OrderSvc = service.NewOrderService(c.OrderRepo, c.ProductRepo, c.UserRepo)
}

func (c *Container) Close() error {
	if c.DB != nil {
		log.Println("Closing database...")
		return c.DB.Close()
	}
	return nil
}
