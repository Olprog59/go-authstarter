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

	"github.com/Olprog59/go-authstarter/internal/config"
	"github.com/Olprog59/go-authstarter/internal/metrics"
	"github.com/Olprog59/go-authstarter/internal/ports"
	"github.com/Olprog59/go-authstarter/internal/repository"
	"github.com/Olprog59/go-authstarter/internal/repository/db"
	"github.com/Olprog59/go-authstarter/internal/service"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/source/file" // Required for file-based migrations
	_ "github.com/go-sql-driver/mysql"                   // MySQL driver
	_ "github.com/lib/pq"                                 // PostgreSQL driver
	_ "modernc.org/sqlite"                                // SQLite driver
)

// Container holds application dependencies / Contient les dépendances de l'application
type Container struct {
	DB                *sql.DB
	UserRepo          ports.UserRepository
	UserSvc           *service.UserService
	AuthSvc           *service.AuthService
	PasswordSvc       *service.PasswordService
	VerificationSvc   *service.VerificationService
	Config            *config.Config
	RefreshTokenStore ports.RefreshTokenStore
	Metrics           *metrics.Metrics
	ctxCancel         context.CancelFunc
}

// NewContainer initializes application container / Initialise le conteneur de l'application
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

	if err := c.initRepositories(); err != nil {
		c.Close()
		return nil, fmt.Errorf("repository init: %w", err)
	}

	if err := c.initServices(); err != nil {
		c.Close()
		return nil, fmt.Errorf("service init: %w", err)
	}

	// Update database connection metrics
	c.updateDatabaseMetrics()

	return c, nil
}

// initDatabase initializes database connection / Initialise la connexion à la base de données
func (c *Container) initDatabase() error {
	// Parse database type
	dbType := db.DatabaseType(strings.ToLower(c.Config.Database.Type))
	if dbType == "" {
		dbType = db.SQLite
	}

	// Create database configuration
	dbConfig := db.DatabaseConfig{
		Type:         dbType,
		DSN:          c.Config.Database.DSN,
		MaxOpenConns: c.Config.Database.MaxOpenConns,
		MaxIdleConns: c.Config.Database.MaxIdleConns,
	}

	// Use Factory Pattern to create appropriate initializer
	initializer := db.NewDatabaseInitializer(dbType)

	// Initialize database connection
	database, err := initializer.Initialize(dbConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize %s database: %w", dbType, err)
	}

	c.DB = database
	return nil
}

// runMigrations applies database migrations / Applique les migrations de base de données
func (c *Container) runMigrations() error {
	// Parse database type
	dbType := db.DatabaseType(strings.ToLower(c.Config.Database.Type))
	if dbType == "" {
		dbType = db.SQLite
	}

	// Create migration driver registry (Dependency Injection)
	registry := db.NewMigrationDriverRegistry()

	// Get the appropriate migration driver factory (NO SWITCH!)
	driverFactory, err := registry.GetFactory(dbType)
	if err != nil {
		return err
	}

	// Create the migration driver using the factory
	driver, err := driverFactory.CreateDriver(c.DB)
	if err != nil {
		return fmt.Errorf("could not create %s migration driver: %w", dbType, err)
	}

	// Create migrate instance
	m, err := migrate.NewWithDatabaseInstance(
		"file://"+c.Config.Database.MigrationsPath,
		driverFactory.DriverName(),
		driver,
	)
	if err != nil {
		return fmt.Errorf("could not create migrate instance: %w", err)
	}

	log.Printf("Applying %s database migrations...", dbType)
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migration failed: %w", err)
	}

	log.Println("Database migrations applied successfully.")
	return nil
}

// initRepositories initializes repositories / Initialise les repositories
func (c *Container) initRepositories() error {
	// Use Adapter Pattern for clean database abstraction
	adapter := repository.NewAdapter(c.DB, c.Config.Database.Type)

	// Get repositories from adapter
	c.UserRepo = adapter.UserRepository()
	c.RefreshTokenStore = adapter.RefreshTokenStore()

	log.Printf("Repositories initialized for %s database", c.Config.Database.Type)
	return nil
}

// initServices initializes application services / Initialise les services applicatifs
func (c *Container) initServices() error {
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

// updateDatabaseMetrics updates database metrics / Met à jour les métriques de la BD
func (c *Container) updateDatabaseMetrics() {
	stats := c.DB.Stats()
	c.Metrics.UpdateDatabaseConnections(stats.OpenConnections)
}

// startBackupRoutine starts automatic backup routine / Démarre la routine de backup automatique
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

// performBackup creates database backup / Crée un backup de la base de données
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

// cleanOldBackups removes old backups / Supprime les anciens backups
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

// Close performs graceful shutdown / Effectue un arrêt gracieux
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
