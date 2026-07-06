package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port                      string
	TokenTTL                  time.Duration
	AutomationTokenTTL        time.Duration
	JWTSigningKey             string
	JWTIssuer                 string
	JWTAudience               string
	JWTClockSkew              time.Duration
	ChangeRequestURL          string
	ServerInventoryURL        string
	ServerInventoryStaticJSON string
	UpstreamClientTimeout     time.Duration
	KubernetesAPIURL          string
	KubernetesTokenFile       string
	KubernetesCAFile          string
	AutomationAudience        string
	AutomationNamespace       string
	AutomationServiceAccount  string
	AutomationServiceAccounts []string
}

func Load() Config {
	return Config{
		Port:                      env("PORT", "8082"),
		TokenTTL:                  secondsEnv("SESSION_TOKEN_TTL_SECONDS", 300),
		AutomationTokenTTL:        secondsEnv("AUTOMATION_TOKEN_TTL_SECONDS", 600),
		JWTSigningKey:             os.Getenv("JWT_SIGNING_KEY"),
		JWTIssuer:                 env("JWT_ISSUER", "dendenmushi-sts"),
		JWTAudience:               env("JWT_AUDIENCE", "dendenmushi-session"),
		JWTClockSkew:              secondsEnv("JWT_CLOCK_SKEW_SECONDS", 5),
		ChangeRequestURL:          os.Getenv("CHANGE_REQUEST_URL"),
		ServerInventoryURL:        os.Getenv("SERVER_INVENTORY_URL"),
		ServerInventoryStaticJSON: os.Getenv("SERVER_INVENTORY_STATIC_JSON"),
		UpstreamClientTimeout:     secondsEnv("UPSTREAM_CLIENT_TIMEOUT_SECONDS", 5),
		KubernetesAPIURL:          env("KUBERNETES_API_URL", "https://kubernetes.default.svc"),
		KubernetesTokenFile:       env("KUBERNETES_TOKEN_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
		KubernetesCAFile:          env("KUBERNETES_CA_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"),
		AutomationAudience:        env("AUTOMATION_WORKLOAD_AUDIENCE", "dendenmushi-incident-agent"),
		AutomationNamespace:       env("AUTOMATION_WORKLOAD_NAMESPACE", "dendenmushi"),
		AutomationServiceAccount:  env("AUTOMATION_WORKLOAD_SERVICE_ACCOUNT", "incident-agent"),
		AutomationServiceAccounts: splitEnv("AUTOMATION_WORKLOAD_SERVICE_ACCOUNTS", env("AUTOMATION_WORKLOAD_SERVICE_ACCOUNT", "incident-agent")),
	}
}

func (c Config) Validate() error {
	if len(c.JWTSigningKey) < 32 {
		return errors.New("JWT_SIGNING_KEY must be at least 32 bytes")
	}
	if c.TokenTTL <= 0 {
		return errors.New("SESSION_TOKEN_TTL_SECONDS must be positive")
	}
	if c.AutomationTokenTTL <= 0 {
		return errors.New("AUTOMATION_TOKEN_TTL_SECONDS must be positive")
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

func splitEnv(key, fallback string) []string {
	value := env(key, fallback)
	var values []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			values = append(values, part)
		}
	}
	return values
}
