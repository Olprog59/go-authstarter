package config

import "os"

type Config struct {
	Addr        string
	DatabaseURL string
	Environment string
	JWTToken    string
}

func NewEnv() *Config {
	return &Config{
		Addr:        getEnv("ADDR", ":8080"),
		DatabaseURL: getEnv("DATABASE_URL", "file:./data.db?_journal_mode=wal"),
		Environment: getEnv("ENV", "development"),
		JWTToken:    getEnv("JWT_TOKEN", "kXT5D52SUy79BN7FWcK9tKyajDsXVQ5ptB3sK36k8pwjpxnARqXHLmWeeBNEJKt9RD7Pu33VVpPgeXKbby3CQNxQWq2tXDc24VYJyztga9w8M7STmNGrvkSwTc76bcsK"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
