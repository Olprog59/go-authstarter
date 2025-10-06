package app

import (
	"os"
	"testing"

	"github.com/Olprog59/go-fun/internal/config"
)

func testConfig() *config.Config {
	return &config.Config{
		DatabaseURL: ":memory:",
	}
}

func TestNewContainer_Success(t *testing.T) {
	cfg := testConfig()
	c, err := NewContainer(cfg)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if c.DB == nil {
		t.Error("expected DB to be initialized")
	}
	if c.UserRepo == nil {
		t.Error("expected UserRepo to be initialized")
	}
	if c.UserSvc == nil {
		t.Error("expected UserSvc to be initialized")
	}
	defer c.Close()
}

func TestContainer_Close(t *testing.T) {
	cfg := testConfig()
	c, err := NewContainer(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("expected no error on close, got %v", err)
	}
}

func TestNewContainer_BadDB(t *testing.T) {
	cfg := &config.Config{DatabaseURL: "/invalid/path/to/db.sqlite"}
	_, err := NewContainer(cfg)
	if err == nil {
		t.Error("expected error with invalid db path, got nil")
	}
}

func TestMigrate_Idempotent(t *testing.T) {
	cfg := testConfig()
	c, err := NewContainer(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer c.Close()
	// Should not error if run again
	if err := c.migrate(); err != nil {
		t.Errorf("expected idempotent migrate, got %v", err)
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	os.Exit(code)
}
