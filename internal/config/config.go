package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port                  string
	TokenTTL              time.Duration
	ChangeRequestURL      string
	ServerInventoryURL    string
	UpstreamClientTimeout time.Duration
}

func Load() Config {
	return Config{
		Port:                  env("PORT", "8082"),
		TokenTTL:              secondsEnv("SESSION_TOKEN_TTL_SECONDS", 300),
		ChangeRequestURL:      os.Getenv("CHANGE_REQUEST_URL"),
		ServerInventoryURL:    os.Getenv("SERVER_INVENTORY_URL"),
		UpstreamClientTimeout: secondsEnv("UPSTREAM_CLIENT_TIMEOUT_SECONDS", 5),
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func secondsEnv(key string, fallback int) time.Duration {
	value, err := strconv.Atoi(env(key, strconv.Itoa(fallback)))
	if err != nil {
		value = fallback
	}
	return time.Duration(value) * time.Second
}
