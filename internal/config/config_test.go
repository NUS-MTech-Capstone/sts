package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestLoadAppliesDefaultsAndFallbacksForInvalidDurations(t *testing.T) {
	t.Setenv("JWT_SIGNING_KEY", "0123456789abcdef0123456789abcdef")
	t.Setenv("SESSION_TOKEN_TTL_SECONDS", "not-a-number")
	t.Setenv("AUTOMATION_TOKEN_TTL_SECONDS", "900")
	t.Setenv("JWT_CLOCK_SKEW_SECONDS", "-1")
	t.Setenv("UPSTREAM_CLIENT_TIMEOUT_SECONDS", "bad")
	t.Setenv("AUTOMATION_WORKLOAD_SERVICE_ACCOUNTS", "incident-agent,agent-controlplane")
	t.Setenv("JWT_ISSUER", "")
	t.Setenv("JWT_AUDIENCE", "")

	cfg := Load()
	if cfg.Port != "8082" || cfg.JWTIssuer != "dendenmushi-sts" || cfg.JWTAudience != "dendenmushi-session" {
		t.Fatalf("defaults not applied: %#v", cfg)
	}
	if cfg.TokenTTL != 300*time.Second || cfg.AutomationTokenTTL != 900*time.Second ||
		cfg.JWTClockSkew != -time.Second || cfg.UpstreamClientTimeout != 5*time.Second {
		t.Fatalf("durations = token %s automation %s skew %s upstream %s", cfg.TokenTTL, cfg.AutomationTokenTTL, cfg.JWTClockSkew, cfg.UpstreamClientTimeout)
	}
	if strings.Join(cfg.AutomationServiceAccounts, ",") != "incident-agent,agent-controlplane" {
		t.Fatalf("automation service accounts = %#v", cfg.AutomationServiceAccounts)
	}
}

func TestConfigValidate(t *testing.T) {
	valid := Config{
		TokenTTL:           time.Minute,
		AutomationTokenTTL: 10 * time.Minute,
		JWTSigningKey:      "0123456789abcdef0123456789abcdef",
		JWTIssuer:          "dendenmushi-sts",
		JWTAudience:        "dendenmushi-session",
		JWTClockSkew:       5 * time.Second,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	invalid := valid
	invalid.JWTSigningKey = "too-short"
	if err := invalid.Validate(); err == nil || !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Fatalf("Validate() error = %v, want signing key error", err)
	}

	cases := []struct {
		name      string
		mutate    func(*Config)
		wantError string
	}{
		{name: "session ttl", mutate: func(c *Config) { c.TokenTTL = 0 }, wantError: "SESSION_TOKEN_TTL_SECONDS"},
		{name: "automation ttl", mutate: func(c *Config) { c.AutomationTokenTTL = 0 }, wantError: "AUTOMATION_TOKEN_TTL_SECONDS"},
		{name: "issuer", mutate: func(c *Config) { c.JWTIssuer = "" }, wantError: "JWT_ISSUER"},
		{name: "audience", mutate: func(c *Config) { c.JWTAudience = "" }, wantError: "JWT_AUDIENCE"},
		{name: "clock skew", mutate: func(c *Config) { c.JWTClockSkew = -time.Second }, wantError: "JWT_CLOCK_SKEW_SECONDS"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			tt.mutate(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("Validate() error = %v, want containing %q", err, tt.wantError)
			}
		})
	}
}

func TestEnvUsesFallbackForEmptyValue(t *testing.T) {
	t.Setenv("DDM_EMPTY_TEST", "")
	if value := env("DDM_EMPTY_TEST", "fallback"); value != "fallback" {
		t.Fatalf("env() = %q, want fallback", value)
	}
	if err := os.Setenv("DDM_EMPTY_TEST", "value"); err != nil {
		t.Fatal(err)
	}
	if value := env("DDM_EMPTY_TEST", "fallback"); value != "value" {
		t.Fatalf("env() = %q, want value", value)
	}
}

func TestBoolEnvParsesValuesAndFallbacks(t *testing.T) {
	t.Setenv("DDM_BOOL_TEST", "")
	if got := boolEnv("DDM_BOOL_TEST", true); !got {
		t.Fatal("boolEnv(empty) did not use true fallback")
	}
	t.Setenv("DDM_BOOL_TEST", "false")
	if got := boolEnv("DDM_BOOL_TEST", true); got {
		t.Fatal("boolEnv(false) = true")
	}
	t.Setenv("DDM_BOOL_TEST", "not-a-bool")
	if got := boolEnv("DDM_BOOL_TEST", true); !got {
		t.Fatal("boolEnv(invalid) did not use true fallback")
	}
}
