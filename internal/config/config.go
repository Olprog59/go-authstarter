package config

import (
	"errors"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// Config holds all application configuration / Contient toute la configuration de l'application
type Config struct {
	Server            ServerConfig      `mapstructure:"server"`
	Environment       string            `mapstructure:"environment"`
	Database          DatabaseConfig    `mapstructure:"database"`
	Backup            BackupConfig      `mapstructure:"backup"`
	Auth              AuthConfig        `mapstructure:"auth"`
	Security          SecurityConfig    `mapstructure:"security"`
	EmailVerification EmailVerification `mapstructure:"email_verification"`
	Cors              CorsConfig        `mapstructure:"cors"`
	RateLimiter       RateLimiterConfig `mapstructure:"rate_limiter"`
	SMTP              SMTPConfig        `mapstructure:"smtp"`
	Logging           LoggingConfig     `mapstructure:"logging"`
}

// ServerConfig holds server configuration / Configuration serveur
type ServerConfig struct {
	Port         string        `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"`
	BaseURL      string        `mapstructure:"base_url"`
	FrontendURL  string        `mapstructure:"frontend_url"`
}

// EmailVerification holds email verification config / Configuration vérification email
type EmailVerification struct {
	TokenExpiration time.Duration `mapstructure:"token_expiration"`
}

// DatabaseConfig holds database-specific configuration / Configuration de la base de données
type DatabaseConfig struct {
	DSN            string `mapstructure:"dsn"`             // Data Source Name for connecting to the database
	MigrationsPath string `mapstructure:"migrations_path"` // Path to migration files
	MaxOpenConns   int    `mapstructure:"max_open_conns"`  // Maximum number of open connections (default: 25)
	MaxIdleConns   int    `mapstructure:"max_idle_conns"`  // Maximum number of idle connections (default: 5)
}

// BackupConfig holds database backup configuration / Configuration des sauvegardes de la base de données
type BackupConfig struct {
	Enabled       bool          `mapstructure:"enabled"`        // Enable automatic backups / Active les sauvegardes automatiques
	Interval      time.Duration `mapstructure:"interval"`       // Backup interval (default: 24h) / Intervalle de sauvegarde
	Path          string        `mapstructure:"path"`           // Directory to store backups / Répertoire de stockage
	RetentionDays int           `mapstructure:"retention_days"` // Number of days to keep backups / Nombre de jours de rétention
}

// AuthConfig holds JWT and cookie configuration / Configuration JWT et cookies
type AuthConfig struct {
	JWTSecret            string        `mapstructure:"jwt_secret"`
	AccessTokenDuration  time.Duration `mapstructure:"access_token_duration"`
	RefreshTokenDuration time.Duration `mapstructure:"refresh_token_duration"`
	CookieDomain         string        `mapstructure:"cookie_domain"`
	CookiePath           string        `mapstructure:"cookie_path"`
	CookieSecure         bool          `mapstructure:"cookie_secure"`
}

// SecurityConfig holds security settings / Paramètres de sécurité
type SecurityConfig struct {
	MaxFailedAttempts int           `mapstructure:"max_failed_attempts"`
	LockoutDuration   time.Duration `mapstructure:"lockout_duration"`
	BcryptCost        int           `mapstructure:"bcrypt_cost"`
	TrustedProxies    []string      `mapstructure:"trusted_proxies"`
}

// CorsConfig holds CORS configuration / Configuration CORS
type CorsConfig struct {
	AllowedOrigins []string `mapstructure:"allowed_origins"`
}

// RateLimiterConfig holds rate limiter configuration / Configuration limiteur de débit
type RateLimiterConfig struct {
	RPS     float64 `mapstructure:"rps"`
	Burst   int     `mapstructure:"burst"`
	Enabled bool    `mapstructure:"enabled"`
}

// SMTPConfig holds SMTP server configuration / Configuration serveur SMTP
type SMTPConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	From     string `mapstructure:"from"`
}

// LoggingConfig holds logging configuration / Configuration logging
type LoggingConfig struct {
	Level         string            `mapstructure:"level"`
	Format        string            `mapstructure:"format"`
	LokiEnabled   bool              `mapstructure:"loki_enabled"`
	LokiURL       string            `mapstructure:"loki_url"`
	LokiLabels    map[string]string `mapstructure:"loki_labels"`
	LokiBatchSize int               `mapstructure:"loki_batch_size"`
}

// IsProduction returns true if the application's environment is set to "production".
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// IsProd is an alias for IsProduction, returning true if the environment is "production".
func (c *Config) IsProd() bool {
	return c.IsProduction()
}

// IsDevelopment returns true if the application's environment is set to "development".
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// IsDev is an alias for IsDevelopment, returning true if the environment is "development".
func (c *Config) IsDev() bool {
	return c.IsDevelopment()
}

// LoadConfig reads configuration from a YAML file named "config.yaml" (or "config.yml")
// in the current directory, and then overrides values with environment variables.
//
// The function sets default values for all configuration fields, ensuring the application
// can run even without a configuration file or explicit environment variables.
// Environment variables are prefixed with "APP_" and use underscores instead of dots
// (e.g., `APP_SERVER_PORT` for `server.port`).
//
// It also includes a custom decode hook to correctly parse time.Duration strings.
// After loading, it performs a validation check on the loaded configuration.
//
// Returns:
//   - A pointer to the loaded `Config` struct.
//   - An error if the configuration file cannot be read (unless it's just missing),
//     unmarshaling fails, or validation fails.
func LoadConfig() (*Config, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")

	// Default values
	v.SetDefault("server.port", "8080")
	v.SetDefault("server.read_timeout", "10s")
	v.SetDefault("server.write_timeout", "10s")
	v.SetDefault("server.idle_timeout", "120s")
	v.SetDefault("server.frontend_url", "http://localhost:5173")
	v.SetDefault("environment", "development")
	v.SetDefault("database.dsn", "data.db?_journal_mode=WAL&_busy_timeout=5000")
	v.SetDefault("database.migrations_path", "migrations")
	v.SetDefault("auth.jwt_secret", "your-super-secret-key")
	v.SetDefault("auth.access_token_duration", "15m")
	v.SetDefault("auth.refresh_token_duration", "720h")
	v.SetDefault("auth.cookie_domain", "localhost")
	v.SetDefault("auth.cookie_path", "/")
	v.SetDefault("auth.cookie_secure", false)
	v.SetDefault("security.max_failed_attempts", 5)
	v.SetDefault("security.lockout_duration", "15m")
	v.SetDefault("security.bcrypt_cost", 12)
	v.SetDefault("security.trusted_proxies", []string{}) // Empty by default - don't trust proxy headers unless explicitly configured
	v.SetDefault("cors.allowed_origins", []string{"http://localhost:5173"})

	v.SetDefault("email_verification.token_expiration", "24h")

	// Rate limiter defaults - More permissive in dev
	v.SetDefault("rate_limiter.rps", 10)
	v.SetDefault("rate_limiter.burst", 20)
	v.SetDefault("rate_limiter.enabled", true)

	v.SetDefault("smtp.host", "localhost")
	v.SetDefault("smtp.port", 1025)
	v.SetDefault("smtp.username", "")
	v.SetDefault("smtp.password", "")
	v.SetDefault("smtp.from", "no-reply@go-fun.dev")

	// Backup defaults
	v.SetDefault("backup.enabled", false)
	v.SetDefault("backup.interval", "24h")
	v.SetDefault("backup.path", "./backups")
	v.SetDefault("backup.retention_days", 7)

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "text")
	v.SetDefault("logging.loki_enabled", false)
	v.SetDefault("logging.loki_url", "http://localhost:3100")
	v.SetDefault("logging.loki_labels", map[string]string{
		"app":         "go-authstarter",
		"environment": "development",
	})
	v.SetDefault("logging.loki_batch_size", 10)

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	v.SetEnvPrefix("APP")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Bind specific environment variables
	v.BindEnv("auth.jwt_secret", "JWT_SECRET")
	v.BindEnv("database.dsn", "DATABASE_DSN")
	v.BindEnv("smtp.username", "SMTP_USERNAME")
	v.BindEnv("smtp.password", "SMTP_PASSWORD")

	var cfg Config
	err := v.Unmarshal(&cfg, func(c *mapstructure.DecoderConfig) {
		c.DecodeHook = mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
		)
	})
	if err != nil {
		return nil, err
	}

	// Validation
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Validate checks that the loaded configuration is valid and meets all necessary requirements.
// It performs both general validation and environment-specific checks.
//
// Key validation rules include:
// - Server port and JWT secret are mandatory.
// - In "production" environment:
//   - JWT secret must be at least 32 characters long for cryptographic strength.
//   - Cookies must be marked as secure (HTTPS only).
//   - Database DSN is required.
// - Access and refresh token durations must be positive.
// - If rate limiting is enabled, RPS (requests per second) and burst values must be positive.
//
// Returns:
//   - An error if any validation rule is violated, providing a descriptive message.
//   - `nil` if the configuration is valid.
func (c *Config) Validate() error {
	if c.Server.Port == "" {
		return errors.New("server.port is required")
	}

	if c.Auth.JWTSecret == "" {
		return errors.New("auth.jwt_secret is required")
	}

	// Strict validation in production
	if c.IsProduction() {
		if len(c.Auth.JWTSecret) < 32 {
			return errors.New("auth.jwt_secret must be ≥32 chars in production")
		}
		// Fail if using default JWT secret in production (security risk)
		if c.Auth.JWTSecret == "your-super-secret-key" {
			return errors.New("auth.jwt_secret cannot use default value in production - set JWT_SECRET environment variable")
		}
		if !c.Auth.CookieSecure {
			return errors.New("auth.cookie_secure must be true in production")
		}
		if c.Database.DSN == "" {
			return errors.New("database.dsn is required in production")
		}
	}

	if c.Auth.AccessTokenDuration <= 0 {
		return errors.New("auth.access_token_duration must be positive")
	}

	if c.Auth.RefreshTokenDuration <= 0 {
		return errors.New("auth.refresh_token_duration must be positive")
	}

	if c.RateLimiter.Enabled {
		if c.RateLimiter.RPS <= 0 {
			return errors.New("rate_limiter.rps must be positive when enabled")
		}
		if c.RateLimiter.Burst <= 0 {
			return errors.New("rate_limiter.burst must be positive when enabled")
		}
	}

	return nil
}
