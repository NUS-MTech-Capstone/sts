package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port     string
	TokenTTL time.Duration
}

func Load() Config {
	ttl, err := strconv.Atoi(env("SESSION_TOKEN_TTL_SECONDS", "300"))
	if err != nil {
		ttl = 300
	}
	return Config{Port: env("PORT", "8082"), TokenTTL: time.Duration(ttl) * time.Second}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
