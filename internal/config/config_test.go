package config

import (
	"os"
	"testing"
	"time"
)

func TestConfig_IsProduction(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want bool
	}{
		{"Production environment", "production", true},
		{"Development environment", "development", false},
		{"Empty environment", "", false},
		{"Other environment", "staging", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Environment: tt.env}
			if got := cfg.IsProduction(); got != tt.want {
				t.Errorf("IsProduction() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_IsProd(t *testing.T) {
	cfg := &Config{Environment: "production"}
	if !cfg.IsProd() {
		t.Error("IsProd() should return true for production environment")
	}

	cfg.Environment = "development"
	if cfg.IsProd() {
		t.Error("IsProd() should return false for development environment")
	}
}

func TestConfig_IsDevelopment(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want bool
	}{
		{"Development environment", "development", true},
		{"Production environment", "production", false},
		{"Empty environment", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Environment: tt.env}
			if got := cfg.IsDevelopment(); got != tt.want {
				t.Errorf("IsDevelopment() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_IsDev(t *testing.T) {
	cfg := &Config{Environment: "development"}
	if !cfg.IsDev() {
		t.Error("IsDev() should return true for development environment")
	}

	cfg.Environment = "production"
	if cfg.IsDev() {
		t.Error("IsDev() should return false for production environment")
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name          string
		config        *Config
		expectError   bool
		errorContains string
	}{
		{
			name: "Valid development config",
			config: &Config{
				Server: ServerConfig{
					Port: "8080",
				},
				Auth: AuthConfig{
					JWTSecret:            "development-secret-key",
					AccessTokenDuration:  15 * time.Minute,
					RefreshTokenDuration: 24 * time.Hour,
				},
				RateLimiter: RateLimiterConfig{
					Enabled: true,
					RPS:     10,
					Burst:   20,
				},
				Environment: "development",
			},
			expectError: false,
		},
		{
			name: "Missing server port",
			config: &Config{
				Server: ServerConfig{
					Port: "",
				},
				Auth: AuthConfig{
					JWTSecret:            "test-secret",
					AccessTokenDuration:  15 * time.Minute,
					RefreshTokenDuration: 24 * time.Hour,
				},
			},
			expectError:   true,
			errorContains: "port",
		},
		{
			name: "Missing JWT secret",
			config: &Config{
				Server: ServerConfig{
					Port: "8080",
				},
				Auth: AuthConfig{
					JWTSecret:            "",
					AccessTokenDuration:  15 * time.Minute,
					RefreshTokenDuration: 24 * time.Hour,
				},
			},
			expectError:   true,
			errorContains: "jwt_secret",
		},
		{
			name: "Production with weak JWT secret",
			config: &Config{
				Server: ServerConfig{
					Port: "8080",
				},
				Auth: AuthConfig{
					JWTSecret:            "short",
					AccessTokenDuration:  15 * time.Minute,
					RefreshTokenDuration: 24 * time.Hour,
					CookieSecure:         true,
				},
				Database: DatabaseConfig{
					DSN: "production.db",
				},
				Environment: "production",
			},
			expectError:   true,
			errorContains: "32 chars",
		},
		{
			name: "Production without secure cookies",
			config: &Config{
				Server: ServerConfig{
					Port: "8080",
				},
				Auth: AuthConfig{
					JWTSecret:            "very-long-production-secret-key-32-chars-minimum",
					AccessTokenDuration:  15 * time.Minute,
					RefreshTokenDuration: 24 * time.Hour,
					CookieSecure:         false,
				},
				Database: DatabaseConfig{
					DSN: "production.db",
				},
				Environment: "production",
			},
			expectError:   true,
			errorContains: "cookie_secure",
		},
		{
			name: "Production without database DSN",
			config: &Config{
				Server: ServerConfig{
					Port: "8080",
				},
				Auth: AuthConfig{
					JWTSecret:            "very-long-production-secret-key-32-chars-minimum",
					AccessTokenDuration:  15 * time.Minute,
					RefreshTokenDuration: 24 * time.Hour,
					CookieSecure:         true,
				},
				Database: DatabaseConfig{
					DSN: "",
				},
				Environment: "production",
			},
			expectError:   true,
			errorContains: "database.dsn",
		},
		{
			name: "Valid production config",
			config: &Config{
				Server: ServerConfig{
					Port: "8080",
				},
				Auth: AuthConfig{
					JWTSecret:            "very-long-production-secret-key-32-chars-minimum",
					AccessTokenDuration:  15 * time.Minute,
					RefreshTokenDuration: 24 * time.Hour,
					CookieSecure:         true,
				},
				Database: DatabaseConfig{
					DSN: "production.db",
				},
				RateLimiter: RateLimiterConfig{
					Enabled: true,
					RPS:     10,
					Burst:   20,
				},
				Environment: "production",
			},
			expectError: false,
		},
		{
			name: "Zero access token duration",
			config: &Config{
				Server: ServerConfig{
					Port: "8080",
				},
				Auth: AuthConfig{
					JWTSecret:            "test-secret",
					AccessTokenDuration:  0,
					RefreshTokenDuration: 24 * time.Hour,
				},
			},
			expectError:   true,
			errorContains: "access_token_duration",
		},
		{
			name: "Zero refresh token duration",
			config: &Config{
				Server: ServerConfig{
					Port: "8080",
				},
				Auth: AuthConfig{
					JWTSecret:            "test-secret",
					AccessTokenDuration:  15 * time.Minute,
					RefreshTokenDuration: 0,
				},
			},
			expectError:   true,
			errorContains: "refresh_token_duration",
		},
		{
			name: "Rate limiter enabled with zero RPS",
			config: &Config{
				Server: ServerConfig{
					Port: "8080",
				},
				Auth: AuthConfig{
					JWTSecret:            "test-secret",
					AccessTokenDuration:  15 * time.Minute,
					RefreshTokenDuration: 24 * time.Hour,
				},
				RateLimiter: RateLimiterConfig{
					Enabled: true,
					RPS:     0,
					Burst:   20,
				},
			},
			expectError:   true,
			errorContains: "rps",
		},
		{
			name: "Rate limiter enabled with zero burst",
			config: &Config{
				Server: ServerConfig{
					Port: "8080",
				},
				Auth: AuthConfig{
					JWTSecret:            "test-secret",
					AccessTokenDuration:  15 * time.Minute,
					RefreshTokenDuration: 24 * time.Hour,
				},
				RateLimiter: RateLimiterConfig{
					Enabled: true,
					RPS:     10,
					Burst:   0,
				},
			},
			expectError:   true,
			errorContains: "burst",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errorContains != "" {
					if !contains(err.Error(), tt.errorContains) {
						t.Errorf("Expected error containing '%s', got '%s'", tt.errorContains, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	// Clear environment variables to test defaults
	os.Clearenv()

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config with defaults: %v", err)
	}

	// Verify some defaults
	if cfg.Server.Port != "8080" {
		t.Errorf("Expected default port 8080, got %s", cfg.Server.Port)
	}

	if cfg.Environment != "development" {
		t.Errorf("Expected default environment 'development', got %s", cfg.Environment)
	}

	if cfg.Auth.AccessTokenDuration != 15*time.Minute {
		t.Errorf("Expected default access token duration 15m, got %v", cfg.Auth.AccessTokenDuration)
	}
}

func TestLoadConfig_WithEnvironmentVariables(t *testing.T) {
	// Set environment variables
	os.Setenv("APP_SERVER_PORT", "9000")
	os.Setenv("APP_ENVIRONMENT", "test")
	defer func() {
		os.Unsetenv("APP_SERVER_PORT")
		os.Unsetenv("APP_ENVIRONMENT")
	}()

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Server.Port != "9000" {
		t.Errorf("Expected port from env 9000, got %s", cfg.Server.Port)
	}

	if cfg.Environment != "test" {
		t.Errorf("Expected environment from env 'test', got %s", cfg.Environment)
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && len(s) >= len(substr) &&
		(s == substr || (len(s) > len(substr) && searchString(s, substr)))
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
