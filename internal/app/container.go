package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Olprog59/go-fun/internal/config"
	"github.com/Olprog59/go-fun/internal/metrics"
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

	// Services (business logic) - now refactored into focused, single-responsibility services
	UserSvc         *service.UserService         // Service for user CRUD operations
	AuthSvc         *service.AuthService         // Service for authentication (login, token refresh)
	PasswordSvc     *service.PasswordService     // Service for password operations (reset, change)
	VerificationSvc *service.VerificationService // Service for email verification

	Config            *config.Config          // Application configuration settings.
	RefreshTokenStore ports.RefreshTokenStore // Store for managing refresh tokens.
	Metrics           *metrics.Metrics        // Prometheus metrics collectors.

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

	// Initialize metrics first (no dependencies)
	c.Metrics = metrics.NewMetrics(nil)

	if err := c.initDatabase(); err != nil {
		return nil, fmt.Errorf("database init: %w", err)
	}

	if err := c.runMigrations(); err != nil {
		c.Close() // Ensure database connection is closed on migration failure
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	c.initRepositories()
	if err := c.initServices(); err != nil {
		c.Close()
		return nil, fmt.Errorf("service init: %w", err)
	}

	// Update database connection metrics
	c.updateDatabaseMetrics()

	return c, nil
}

// initDatabase initializes the SQLite database connection and applies PRAGMA settings
// for optimal performance and security.
//
// This function performs the following steps:
// 1.  Opens a new SQLite database connection using the DSN from the configuration.
// 2.  Sets connection pool parameters (MaxOpenConns, MaxIdleConns).
// 3.  Applies various PRAGMA statements to configure SQLite behavior, such as:
//   - `journal_mode=WAL`: Improves concurrency and durability.
//   - `synchronous=NORMAL`: Balances durability and performance.
//   - `busy_timeout`: Sets a timeout for busy connections.
//   - `foreign_keys=ON`: Enforces referential integrity.
//   - `trusted_schema=OFF`: Enhances security by preventing malicious schema changes.
//
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

	// Set connection pool limits from config with defaults / Définit les limites du pool depuis la config avec défauts
	maxOpenConns := c.Config.Database.MaxOpenConns
	if maxOpenConns == 0 {
		maxOpenConns = 25 // Default value
	}
	maxIdleConns := c.Config.Database.MaxIdleConns
	if maxIdleConns == 0 {
		maxIdleConns = 5 // Default value
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)

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
//  1. Creates a new SQLite database driver instance from the existing `sql.DB` connection.
//  2. Initializes a `migrate` instance, pointing to the migration files located in the
//     "file://migrations" directory.
//  3. Executes all pending "up" migrations. If there are no changes, it logs a message
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
		"file://"+c.Config.Database.MigrationsPath,
		"sqlite3",
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
// Initializes services with template parsing validation / Initialise les services avec validation du parsing de templates
func (c *Container) initServices() error {
	c.RefreshTokenStore = repository.NewSQLiteRefreshTokenStore(c.DB)

	// Create EmailService with validation / Crée le service email avec validation
	emailSvc, err := service.NewEmailService(c.Config)
	if err != nil {
		return fmt.Errorf("failed to initialize email service: %w", err)
	}

	// Initialize all services with their dependencies
	c.UserSvc = service.NewUserService(c.UserRepo, c.RefreshTokenStore, c.Config)
	c.AuthSvc = service.NewAuthService(c.UserRepo, c.RefreshTokenStore, c.Config, c.DB, c.Metrics)

	c.PasswordSvc, err = service.NewPasswordService(c.UserRepo, c.RefreshTokenStore, emailSvc, c.Config)
	if err != nil {
		return fmt.Errorf("failed to initialize password service: %w", err)
	}

	c.VerificationSvc, err = service.NewVerificationService(c.UserRepo, emailSvc, c.Config)
	if err != nil {
		return fmt.Errorf("failed to initialize verification service: %w", err)
	}

	// Daily purge + clean stop
	ctx, cancel := context.WithCancel(context.Background())
	c.ctxCancel = cancel // add `ctxCancel context.CancelFunc` in Container struct

	go func() {
		c.Metrics.SetBackgroundTaskStatus("token_purge", true)
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := c.RefreshTokenStore.PurgeExpired(context.Background(), time.Now()); err != nil {
					log.Printf("purge failed: %v", err)
				}
			case <-ctx.Done():
				c.Metrics.SetBackgroundTaskStatus("token_purge", false)
				log.Println("purge goroutine stopped")
				return
			}
		}
	}()

	// Start automatic backup goroutine if enabled / Démarre la goroutine de backup automatique si activée
	if c.Config.Backup.Enabled {
		c.startBackupRoutine(ctx)
	}

	return nil
}

// updateDatabaseMetrics updates Prometheus metrics for database connections.
func (c *Container) updateDatabaseMetrics() {
	stats := c.DB.Stats()
	c.Metrics.UpdateDatabaseConnections(stats.OpenConnections)
}

// startBackupRoutine starts automatic database backup goroutine / Démarre la goroutine de backup automatique
func (c *Container) startBackupRoutine(ctx context.Context) {
	go func() {
		c.Metrics.SetBackgroundTaskStatus("database_backup", true)
		ticker := time.NewTicker(c.Config.Backup.Interval)
		defer ticker.Stop()

		log.Printf("Automatic database backup enabled (interval: %s, retention: %d days)",
			c.Config.Backup.Interval, c.Config.Backup.RetentionDays)

		for {
			select {
			case <-ticker.C:
				if err := c.performBackup(); err != nil {
					log.Printf("backup failed: %v", err)
				} else {
					log.Println("database backup completed successfully")
				}
				// Clean old backups after creating new one / Nettoie les anciens backups après création
				if err := c.cleanOldBackups(); err != nil {
					log.Printf("backup cleanup failed: %v", err)
				}
			case <-ctx.Done():
				c.Metrics.SetBackgroundTaskStatus("database_backup", false)
				log.Println("backup goroutine stopped")
				return
			}
		}
	}()
}

// performBackup creates a database backup using VACUUM INTO / Crée un backup de la base de données
func (c *Container) performBackup() error {
	// Create backup directory if not exists / Crée le répertoire de backup s'il n'existe pas
	if err := os.MkdirAll(c.Config.Backup.Path, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Extract database filename from DSN / Extrait le nom du fichier depuis le DSN
	dbName := c.Config.Database.DSN
	if idx := strings.Index(dbName, "?"); idx > 0 {
		dbName = dbName[:idx]
	}
	if dbName == "" || dbName == ":memory:" {
		return fmt.Errorf("cannot backup in-memory database")
	}

	// Generate backup filename with timestamp / Génère le nom du fichier avec horodatage
	timestamp := time.Now().Format("20060102-150405")
	backupFilename := fmt.Sprintf("%s.backup-%s.db", filepath.Base(dbName), timestamp)
	backupPath := filepath.Join(c.Config.Backup.Path, backupFilename)

	// Use VACUUM INTO to create backup (SQLite 3.27.0+) / Utilise VACUUM INTO pour créer le backup
	query := fmt.Sprintf("VACUUM INTO '%s'", backupPath)
	if _, err := c.DB.Exec(query); err != nil {
		return fmt.Errorf("backup execution failed: %w", err)
	}

	log.Printf("Database backup created: %s", backupPath)
	return nil
}

// cleanOldBackups removes backups older than retention period / Supprime les backups plus anciens que la rétention
func (c *Container) cleanOldBackups() error {
	if c.Config.Backup.RetentionDays <= 0 {
		return nil // No cleanup if retention is 0 or negative / Pas de nettoyage si rétention <= 0
	}

	cutoffTime := time.Now().AddDate(0, 0, -c.Config.Backup.RetentionDays)

	entries, err := os.ReadDir(c.Config.Backup.Path)
	if err != nil {
		return fmt.Errorf("failed to read backup directory: %w", err)
	}

	deletedCount := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Only delete .backup-*.db files / Ne supprime que les fichiers .backup-*.db
		if !strings.Contains(entry.Name(), ".backup-") || !strings.HasSuffix(entry.Name(), ".db") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			log.Printf("failed to get file info for %s: %v", entry.Name(), err)
			continue
		}

		if info.ModTime().Before(cutoffTime) {
			backupPath := filepath.Join(c.Config.Backup.Path, entry.Name())
			if err := os.Remove(backupPath); err != nil {
				log.Printf("failed to delete old backup %s: %v", entry.Name(), err)
			} else {
				deletedCount++
				log.Printf("Deleted old backup: %s (age: %d days)",
					entry.Name(), int(time.Since(info.ModTime()).Hours()/24))
			}
		}
	}

	if deletedCount > 0 {
		log.Printf("Cleaned up %d old backup(s)", deletedCount)
	}

	return nil
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
