package config

import (
	"errors"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// Config holds all configuration for the application.
type Config struct {
	Server      ServerConfig      `mapstructure:"server"`
	Environment string            `mapstructure:"environment"`
	Database    DatabaseConfig    `mapstructure:"database"`
	Auth        AuthConfig        `mapstructure:"auth"`
	Cors        CorsConfig        `mapstructure:"cors"`
	RateLimiter RateLimiterConfig `mapstructure:"rate_limiter"`
	SMTP        SMTPConfig        `mapstructure:"smtp"`
}

// ServerConfig holds server-specific configuration.
type ServerConfig struct {
	Port         string        `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"`
}

// DatabaseConfig holds database-specific configuration.
type DatabaseConfig struct {
	DSN string `mapstructure:"dsn"`
}

// AuthConfig holds authentication-specific configuration (JWT, cookies).
type AuthConfig struct {
	JWTSecret            string        `mapstructure:"jwt_secret"`
	AccessTokenDuration  time.Duration `mapstructure:"access_token_duration"`
	RefreshTokenDuration time.Duration `mapstructure:"refresh_token_duration"`
	CookieDomain         string        `mapstructure:"cookie_domain"`
	CookiePath           string        `mapstructure:"cookie_path"`
	CookieSecure         bool          `mapstructure:"cookie_secure"`
}

// CorsConfig holds CORS-specific configuration.
type CorsConfig struct {
	AllowedOrigins []string `mapstructure:"allowed_origins"`
}

// RateLimiterConfig holds rate limiter-specific configuration.
type RateLimiterConfig struct {
	RPS     float64 `mapstructure:"rps"`
	Burst   int     `mapstructure:"burst"`
	Enabled bool    `mapstructure:"enabled"`
}

// SMTPConfig holds SMTP server configuration.
type SMTPConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	From     string `mapstructure:"from"`
}

// IsProduction returns true if the environment is production.
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// IsProd returns true if the environment is production (alias).
func (c *Config) IsProd() bool {
	return c.IsProduction()
}

// IsDevelopment returns true if the environment is development.
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// IsDev returns true if the environment is development (alias).
func (c *Config) IsDev() bool {
	return c.IsDevelopment()
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig() (*Config, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")

	// Valeurs par défaut
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

	// Rate limiter defaults - Plus permissif en dev
	v.SetDefault("rate_limiter.rps", 10)
	v.SetDefault("rate_limiter.burst", 20)
	v.SetDefault("rate_limiter.enabled", true)

	v.SetDefault("smtp.host", "localhost")
	v.SetDefault("smtp.port", 1025)
	v.SetDefault("smtp.username", "")
	v.SetDefault("smtp.password", "")
	v.SetDefault("smtp.from", "no-reply@go-fun.dev")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	v.SetEnvPrefix("APP")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	v.BindEnv("auth.jwt_secret", "JWT_SECRET")

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

// Validate vérifie que la configuration est valide
func (c *Config) Validate() error {
	if c.Server.Port == "" {
		return errors.New("server.port is required")
	}

	if c.Auth.JWTSecret == "" {
		return errors.New("auth.jwt_secret is required")
	}

	// Validation stricte en production
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
