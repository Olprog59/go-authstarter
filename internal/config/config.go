package config

import (
	"errors"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// Config holds all configuration for the application.
// It is the root structure that aggregates various configuration sections
// such as server settings, database connection, authentication parameters,
// email verification, CORS policies, rate limiting, and SMTP details.
// Each field is tagged with `mapstructure` to facilitate unmarshaling
// from configuration files (e.g., YAML) or environment variables.
type Config struct {
	Server            ServerConfig      `mapstructure:"server"`             // Server-specific settings like port, timeouts, and base URL.
	Environment       string            `mapstructure:"environment"`        // The application's running environment (e.g., "development", "production").
	Database          DatabaseConfig    `mapstructure:"database"`           // Database connection string and related settings.
	Auth              AuthConfig        `mapstructure:"auth"`               // Authentication parameters, including JWT secrets and cookie settings.
	EmailVerification EmailVerification `mapstructure:"email_verification"` // Settings for email verification tokens.
	Cors              CorsConfig        `mapstructure:"cors"`               // Cross-Origin Resource Sharing policies.
	RateLimiter       RateLimiterConfig `mapstructure:"rate_limiter"`       // Configuration for API rate limiting.
	SMTP              SMTPConfig        `mapstructure:"smtp"`               // SMTP server details for sending emails.
	Logging           LoggingConfig     `mapstructure:"logging"`            // Logging configuration (console, Loki).
}

// ServerConfig holds server-specific configuration.
type ServerConfig struct {
	Port         string        `mapstructure:"port"`          // The port on which the HTTP server will listen.
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`  // Maximum duration for reading the entire request, including the body.
	WriteTimeout time.Duration `mapstructure:"write_timeout"` // Maximum duration before timing out writes of the response.
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"`  // Maximum amount of time to wait for the next request when keep-alives are enabled.
	BaseURL      string        `mapstructure:"base_url"`      // The base URL of the application, used for constructing links (e.g., email verification).
}

// EmailVerification holds configuration specific to email verification tokens.
type EmailVerification struct {
	TokenExpiration time.Duration `mapstructure:"token_expiration"` // The duration for which an email verification token is valid.
}

// DatabaseConfig holds database-specific configuration.
type DatabaseConfig struct {
	DSN string `mapstructure:"dsn"` // Data Source Name for connecting to the database (e.g., SQLite file path).
}

// AuthConfig holds authentication-specific configuration (JWT, cookies).
type AuthConfig struct {
	JWTSecret            string        `mapstructure:"jwt_secret"`             // The secret key used for signing and verifying JSON Web Tokens.
	AccessTokenDuration  time.Duration `mapstructure:"access_token_duration"`  // The validity duration for access tokens.
	RefreshTokenDuration time.Duration `mapstructure:"refresh_token_duration"` // The validity duration for refresh tokens.
	CookieDomain         string        `mapstructure:"cookie_domain"`          // The domain for which authentication cookies are valid.
	CookiePath           string        `mapstructure:"cookie_path"`            // The path for which authentication cookies are valid.
	CookieSecure         bool          `mapstructure:"cookie_secure"`          // Flag to indicate if cookies should only be sent over HTTPS.
}

// CorsConfig holds CORS-specific configuration.
type CorsConfig struct {
	AllowedOrigins []string `mapstructure:"allowed_origins"` // A list of origins that are allowed to make cross-origin requests.
}

// RateLimiterConfig holds rate limiter-specific configuration.
type RateLimiterConfig struct {
	RPS     float64 `mapstructure:"rps"`     // Requests per second allowed for the rate limiter.
	Burst   int     `mapstructure:"burst"`   // The maximum burst of requests allowed above the RPS limit.
	Enabled bool    `mapstructure:"enabled"` // Flag to enable or disable the rate limiter.
}

// SMTPConfig holds SMTP server configuration.
type SMTPConfig struct {
	Host     string `mapstructure:"host"`     // The hostname or IP address of the SMTP server.
	Port     int    `mapstructure:"port"`     // The port number for the SMTP server.
	Username string `mapstructure:"username"` // The username for SMTP authentication.
	Password string `mapstructure:"password"` // The password for SMTP authentication.
	From     string `mapstructure:"from"`     // The "From" email address for outgoing emails.
}

// LoggingConfig holds logging configuration (console output, Loki integration).
type LoggingConfig struct {
	Level         string            `mapstructure:"level"`          // Logging level: debug, info, warn, error
	Format        string            `mapstructure:"format"`         // Log format: text or json
	LokiEnabled   bool              `mapstructure:"loki_enabled"`   // Enable sending logs to Loki
	LokiURL       string            `mapstructure:"loki_url"`       // Loki server URL (e.g., http://localhost:3100)
	LokiLabels    map[string]string `mapstructure:"loki_labels"`    // Static labels to attach to all logs sent to Loki
	LokiBatchSize int               `mapstructure:"loki_batch_size"` // Number of logs to batch before sending to Loki (0 = immediate)
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
	v.SetDefault("environment", "development")
	v.SetDefault("database.dsn", "data.db?_journal_mode=WAL&_busy_timeout=5000")
	v.SetDefault("auth.jwt_secret", "your-super-secret-key")
	v.SetDefault("auth.access_token_duration", "15m")
	v.SetDefault("auth.refresh_token_duration", "720h")
	v.SetDefault("auth.cookie_domain", "localhost")
	v.SetDefault("auth.cookie_path", "/")
	v.SetDefault("auth.cookie_secure", false)
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
