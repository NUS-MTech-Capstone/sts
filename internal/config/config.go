package config

import (
	"errors"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port                      string
	TokenTTL                  time.Duration
	JWTSigningKey             string
	JWTIssuer                 string
	JWTAudience               string
	JWTClockSkew              time.Duration
	ChangeRequestURL          string
	ServerInventoryURL        string
	ServerInventoryStaticJSON string
	UpstreamClientTimeout     time.Duration
}

func Load() Config {
	return Config{
		Port:                      env("PORT", "8082"),
		TokenTTL:                  secondsEnv("SESSION_TOKEN_TTL_SECONDS", 300),
		JWTSigningKey:             os.Getenv("JWT_SIGNING_KEY"),
		JWTIssuer:                 env("JWT_ISSUER", "dendenmushi-sts"),
		JWTAudience:               env("JWT_AUDIENCE", "dendenmushi-session"),
		JWTClockSkew:              secondsEnv("JWT_CLOCK_SKEW_SECONDS", 5),
		ChangeRequestURL:          os.Getenv("CHANGE_REQUEST_URL"),
		ServerInventoryURL:        os.Getenv("SERVER_INVENTORY_URL"),
		ServerInventoryStaticJSON: os.Getenv("SERVER_INVENTORY_STATIC_JSON"),
		UpstreamClientTimeout:     secondsEnv("UPSTREAM_CLIENT_TIMEOUT_SECONDS", 5),
	}
}

func (c Config) Validate() error {
	if len(c.JWTSigningKey) < 32 {
		return errors.New("JWT_SIGNING_KEY must be at least 32 bytes")
	}
	if c.TokenTTL <= 0 {
		return errors.New("SESSION_TOKEN_TTL_SECONDS must be positive")
	}
	if c.JWTIssuer == "" {
		return errors.New("JWT_ISSUER is required")
	}
	if c.JWTAudience == "" {
		return errors.New("JWT_AUDIENCE is required")
	}
	if c.JWTClockSkew < 0 {
		return errors.New("JWT_CLOCK_SKEW_SECONDS must not be negative")
	}
	return nil
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
