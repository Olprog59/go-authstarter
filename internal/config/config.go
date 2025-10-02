package config

import "os"

type Config struct {
	Addr        string
	DatabaseURL string
	Environment string
}

func NewEnv() *Config {
	return &Config{
		Addr:        getEnv("ADDR", ":8080"),
		DatabaseURL: getEnv("DATABASE_URL", "file:./data.db?_journal_mode=wal"),
		Environment: getEnv("ENV", "development"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
