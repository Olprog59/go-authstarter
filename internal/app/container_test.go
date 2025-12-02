package app_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Olprog59/go-authstarter/internal/app"
	"github.com/Olprog59/go-authstarter/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewContainer(t *testing.T) {
	// Create a temporary directory for migrations
	migrationsDir, err := os.MkdirTemp("", "migrations")
	require.NoError(t, err)
	defer os.RemoveAll(migrationsDir)

	// Create a dummy migration file
	upFile := filepath.Join(migrationsDir, "000001_create_initial_schema.up.sql")
	err = os.WriteFile(upFile, []byte("CREATE TABLE test (id INT);"), 0644)
	require.NoError(t, err)

	// Create a config for an in-memory SQLite database
	cfg := &config.Config{
		Database: config.DatabaseConfig{
			DSN:            ":memory:",
			MigrationsPath: migrationsDir,
		},
		Auth: config.AuthConfig{
			JWTSecret: "test-secret",
			AccessTokenDuration: 1 * time.Minute,
			RefreshTokenDuration: 1 * time.Hour,
		},
		Security: config.SecurityConfig{
			BcryptCost: 4,
		},
		SMTP: config.SMTPConfig{
			Host: "localhost",
			Port: 1025,
			From: "test@example.com",
		},
	}

	// Create a new container
	container, err := app.NewContainer(cfg)
	require.NoError(t, err)
	require.NotNil(t, container)
	defer container.Close()

	// Assert that all fields are initialized
	assert.NotNil(t, container.DB)
	assert.NotNil(t, container.UserRepo)
	assert.NotNil(t, container.UserSvc)
	assert.NotNil(t, container.AuthSvc)
	assert.NotNil(t, container.PasswordSvc)
	assert.NotNil(t, container.VerificationSvc)
	assert.NotNil(t, container.Config)
	assert.NotNil(t, container.RefreshTokenStore)
	assert.NotNil(t, container.Metrics)

	// Check if the database connection is alive
	err = container.DB.Ping()
	assert.NoError(t, err)

	// Check if the migration was applied
	_, err = container.DB.Query("SELECT id FROM test")
	assert.NoError(t, err)
}