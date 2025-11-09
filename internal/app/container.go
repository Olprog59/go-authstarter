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
	_ "github.com/golang-migrate/migrate/v4/source/file" // Required for file-based migrations
	_ "modernc.org/sqlite"                               // SQLite driver
)

// Container is a Dependency Injection Container that groups all application dependencies.
// It follows the Hexagonal Architecture pattern, separating concerns into ports (interfaces)
// and adapters (implementations). This design promotes modularity, testability, and
// maintainability by centralizing dependency creation and management.
type Container struct {
	DB *sql.DB // The main database connection pool.

	// Ports (interfaces) define the boundaries of the application's core logic.
	UserRepo ports.UserRepository // Repository for user data persistence.

	// Services (business logic) encapsulate the application's core use cases.
	UserSvc *service.UserService // Service for user-related operations (e.g., authentication, registration).

	Config            *config.Config            // Application configuration settings.
	RefreshTokenStore ports.RefreshTokenStore // Store for managing refresh tokens.

	ctxCancel context.CancelFunc // Function to cancel the background context for graceful shutdown.
}

// NewContainer initializes and returns a new Container instance with all its dependencies.
// This function orchestrates the setup of the entire application, including:
// 1.  Loading the application configuration.
// 2.  Initializing the database connection and applying any pending migrations.
// 3.  Setting up repository implementations.
// 4.  Initializing business services with their respective dependencies.
// 5.  Starting background tasks, such as the daily refresh token purge.
//
// Parameters:
//   - cfg: The application's configuration settings.
//
// Returns:
//   - A pointer to the initialized `Container` on success.
//   - An error if any initialization step fails (e.g., database connection, migrations).
func NewContainer(cfg *config.Config) (*Container, error) {
	c := &Container{}
	c.Config = cfg

	if err := c.initDatabase(); err != nil {
		return nil, fmt.Errorf("database init: %w", err)
	}

	if err := c.runMigrations(); err != nil {
		c.Close() // Ensure database connection is closed on migration failure
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	c.initRepositories()
	c.initServices()

	return c, nil
}

// initDatabase initializes the SQLite database connection and applies PRAGMA settings
// for optimal performance and security.
//
// This function performs the following steps:
// 1.  Opens a new SQLite database connection using the DSN from the configuration.
// 2.  Sets connection pool parameters (MaxOpenConns, MaxIdleConns).
// 3.  Applies various PRAGMA statements to configure SQLite behavior, such as:
//     - `journal_mode=WAL`: Improves concurrency and durability.
//     - `synchronous=NORMAL`: Balances durability and performance.
//     - `busy_timeout`: Sets a timeout for busy connections.
//     - `foreign_keys=ON`: Enforces referential integrity.
//     - `trusted_schema=OFF`: Enhances security by preventing malicious schema changes.
// 4.  Pings the database to verify the connection is active.
//
// Returns:
//   - An error if the database connection fails or PRAGMA settings cannot be applied.
//   - `nil` on successful initialization.
func (c *Container) initDatabase() error {
	db, err := sql.Open("sqlite", c.Config.Database.DSN)
	if err != nil {
		return err
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)

	// Performance/security adjustments
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
	exec("PRAGMA cache_size=10000;") // negative for pages, positive for KB

	if err := db.Ping(); err != nil {
		db.Close()
		return err
	}

	c.DB = db
	log.Println("Database connected")
	return nil
}

// runMigrations applies database schema migrations using the `golang-migrate` library.
// Migrations are essential for evolving the database schema in a controlled and versioned manner.
//
// This function performs the following steps:
// 1.  Creates a new SQLite database driver instance from the existing `sql.DB` connection.
// 2.  Initializes a `migrate` instance, pointing to the migration files located in the
//     "file://migrations" directory.
// 3.  Executes all pending "up" migrations. If there are no changes, it logs a message
//     and does not return an error.
//
// Returns:
//   - An error if the migration process fails (e.g., invalid migration files, database error).
//   - `nil` if migrations are applied successfully or if there are no new migrations.
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

// initRepositories initializes all concrete implementations of the repository interfaces (ports).
// This function is responsible for wiring up the database-specific adapters to the
// application's repository interfaces, making them available to services.
func (c *Container) initRepositories() {
	c.UserRepo = repository.NewSQLiteUser(c.DB)
}

// initServices initializes all application services (business logic).
// This function creates instances of each service, injecting their required dependencies,
// which often include repository interfaces and configuration settings.
//
// It also sets up background tasks:
// - A goroutine is started to periodically purge expired refresh tokens from the database.
//   This ensures that the token store remains clean and prevents accumulation of stale data.
// - A context cancellation function (`ctxCancel`) is stored to allow for graceful shutdown
//   of this background goroutine when the application closes.
func (c *Container) initServices() {
	c.RefreshTokenStore = repository.NewSQLiteRefreshTokenStore(c.DB)
	c.UserSvc = service.NewUserService(c.UserRepo, c.Config, c.RefreshTokenStore, c.DB)

	// Daily purge + clean stop
	ctx, cancel := context.WithCancel(context.Background())
	c.ctxCancel = cancel // add `ctxCancel context.CancelFunc` in Container struct

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

// Close performs a graceful shutdown of all resources managed by the Container.
// This includes:
// 1.  Canceling any background contexts (e.g., for the refresh token purge goroutine).
// 2.  Closing the database connection pool to release resources.
//
// This method should be called when the application is shutting down to ensure
// all connections are properly closed and background tasks are terminated.
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
