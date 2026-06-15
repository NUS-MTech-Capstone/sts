package config

import (
	"strings"
	"testing"
	"time"
)

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
}
