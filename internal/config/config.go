// Package config provides application configuration management using Viper.
// It supports loading configuration from YAML files and environment variables,
// with built-in validation for production and development environments.
// The package follows a hierarchical configuration structure with support for
// multiple database types (SQLite, MySQL, PostgreSQL), authentication settings,
// security policies, CORS, rate limiting, SMTP, and logging configurations.
package config

import (
	"errors"
	"slices"
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
	TokenExpiration   time.Duration `mapstructure:"token_expiration"`
	ResendCooldown    time.Duration `mapstructure:"resend_cooldown"`     // Minimum time between resend requests per email
	ResendMaxAttempts int           `mapstructure:"resend_max_attempts"` // Maximum resend attempts within cooldown period
}

// DatabaseConfig holds database-specific configuration / Configuration de la base de données
type DatabaseConfig struct {
	Type           string `mapstructure:"type"`            // Database type: "sqlite", "mysql", or "postgres"
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

// IsProduction checks if environment is production / Vérifie si l'environnement est production
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// IsProd is alias for IsProduction / Alias pour IsProduction
func (c *Config) IsProd() bool {
	return c.IsProduction()
}

// IsDevelopment checks if environment is development / Vérifie si l'environnement est development
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// IsDev is alias for IsDevelopment / Alias pour IsDevelopment
func (c *Config) IsDev() bool {
	return c.IsDevelopment()
}

// LoadConfig loads configuration from YAML and env vars / Charge la config depuis YAML et variables d'env
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
	v.SetDefault("database.type", "sqlite")
	v.SetDefault("database.dsn", "data.db?_journal_mode=WAL&_busy_timeout=5000")
	v.SetDefault("database.migrations_path", "migrations/sqlite")
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
	v.SetDefault("email_verification.resend_cooldown", "5m")
	v.SetDefault("email_verification.resend_max_attempts", 3)

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

// Validate validates configuration / Valide la configuration
func (c *Config) Validate() error {
	if err := c.validateServer(); err != nil {
		return err
	}

	if err := c.validateDatabase(); err != nil {
		return err
	}

	if err := c.validateAuth(); err != nil {
		return err
	}

	if err := c.validateRateLimiter(); err != nil {
		return err
	}

	return nil
}

// validateServer validates server configuration
func (c *Config) validateServer() error {
	if c.Server.Port == "" {
		return errors.New("server.port is required")
	}
	return nil
}

// validateDatabase validates database configuration
func (c *Config) validateDatabase() error {
	validDBTypes := []string{"sqlite", "mysql", "postgres", "postgresql", ""}
	dbType := strings.ToLower(c.Database.Type)

	if dbType != "" && !slices.Contains(validDBTypes, dbType) {
		return errors.New("database.type must be one of: sqlite, mysql, postgres")
	}

	// Production-specific database validation
	if c.IsProduction() && c.Database.DSN == "" {
		return errors.New("database.dsn is required in production")
	}

	return nil
}

// validateAuth validates authentication and JWT configuration
func (c *Config) validateAuth() error {
	if c.Auth.JWTSecret == "" {
		return errors.New("auth.jwt_secret is required")
	}

	if err := c.validateJWTSecret(); err != nil {
		return err
	}

	if err := c.validateTokenDurations(); err != nil {
		return err
	}

	// Production-specific auth validation
	if c.IsProduction() && !c.Auth.CookieSecure {
		return errors.New("auth.cookie_secure must be true in production")
	}

	return nil
}

// validateJWTSecret validates JWT secret strength
func (c *Config) validateJWTSecret() error {
	if c.IsProduction() {
		if len(c.Auth.JWTSecret) < 32 {
			return errors.New("auth.jwt_secret must be ≥32 chars in production")
		}
		if c.Auth.JWTSecret == "your-super-secret-key" {
			return errors.New("auth.jwt_secret cannot use default value in production - set JWT_SECRET environment variable")
		}
	}
	return nil
}

// validateTokenDurations validates token duration settings
func (c *Config) validateTokenDurations() error {
	if c.Auth.AccessTokenDuration <= 0 {
		return errors.New("auth.access_token_duration must be positive")
	}

	if c.Auth.RefreshTokenDuration <= 0 {
		return errors.New("auth.refresh_token_duration must be positive")
	}

	return nil
}

// validateRateLimiter validates rate limiter configuration
func (c *Config) validateRateLimiter() error {
	if !c.RateLimiter.Enabled {
		return nil
	}

	if c.RateLimiter.RPS <= 0 {
		return errors.New("rate_limiter.rps must be positive when enabled")
	}

	if c.RateLimiter.Burst <= 0 {
		return errors.New("rate_limiter.burst must be positive when enabled")
	}

	return nil
}
