package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/sts/internal/model"
	"github.com/golang-jwt/jwt/v5"
)

var testNow = time.Date(2026, time.June, 11, 12, 0, 0, 0, time.UTC)

func testTokenConfig() TokenConfig {
	return TokenConfig{
		TTL:        time.Minute,
		SigningKey: []byte("0123456789abcdef0123456789abcdef"),
		Issuer:     "test-sts",
		Audience:   "test-session",
		ClockSkew:  5 * time.Second,
	}
}

func TestIssueAndValidateSessionToken(t *testing.T) {
	svc := New(testTokenConfig(), nil, nil)
	svc.now = func() time.Time { return testNow }
	ctx := context.Background()
	token, err := svc.IssueSessionToken(ctx, model.SessionTokenRequest{SessionID: "sess-1", UserID: "user-1", Mode: "owner"})
	if err != nil {
		t.Fatalf("IssueSessionToken() error = %v", err)
	}
	if token.TokenType != "Bearer" {
		t.Fatalf("TokenType = %q, want Bearer", token.TokenType)
	}
	if token.ExpiresAt != testNow.Add(time.Minute) {
		t.Fatalf("ExpiresAt = %s, want %s", token.ExpiresAt, testNow.Add(time.Minute))
	}

	// A separate service instance can verify the JWT without shared token state.
	verifier := New(testTokenConfig(), nil, nil)
	verifier.now = func() time.Time { return testNow }
	resp := verifier.ValidateSessionToken(ctx, model.TokenValidateRequest{
		SessionID: "sess-1",
		UserID:    "user-1",
		Mode:      "owner",
		Token:     token.SessionToken,
	})
	if !resp.Allowed {
		t.Fatalf("ValidateSessionToken() allowed = false, reason = %s", resp.Reason)
	}

	claims := &sessionClaims{}
	parsed, err := jwt.ParseWithClaims(
		token.SessionToken,
		claims,
		func(_ *jwt.Token) (any, error) { return testTokenConfig().SigningKey, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithoutClaimsValidation(),
	)
	if err != nil || !parsed.Valid {
		t.Fatalf("ParseWithClaims() error = %v", err)
	}
	if claims.Issuer != "test-sts" || claims.Subject != "user-1" ||
		len(claims.Audience) != 1 || claims.Audience[0] != "test-session" ||
		claims.SessionID != "sess-1" || claims.Mode != "owner" ||
		claims.ExpiresAt == nil || claims.IssuedAt == nil || claims.NotBefore == nil || claims.ID == "" {
		t.Fatalf("unexpected claims: %#v", claims)
	}
}

func TestValidateSessionTokenRejectsWrongUserOrMode(t *testing.T) {
	svc := New(testTokenConfig(), nil, nil)
	svc.now = func() time.Time { return testNow }
	token, err := svc.IssueSessionToken(t.Context(), model.SessionTokenRequest{
		SessionID: "sess-1",
		UserID:    "user-1",
		Mode:      "observer",
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		req  model.TokenValidateRequest
	}{
		{
			name: "user",
			req: model.TokenValidateRequest{
				SessionID: "sess-1",
				UserID:    "other-user",
				Mode:      "observer",
				Token:     token.SessionToken,
			},
		},
		{
			name: "mode",
			req: model.TokenValidateRequest{
				SessionID: "sess-1",
				UserID:    "user-1",
				Mode:      "owner",
				Token:     token.SessionToken,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if resp := svc.ValidateSessionToken(t.Context(), test.req); resp.Allowed {
				t.Fatal("ValidateSessionToken() allowed mismatched token")
			}
		})
	}
}

func TestValidateSessionTokenRejectsExpiredOrTamperedJWT(t *testing.T) {
	svc := New(testTokenConfig(), nil, nil)
	svc.now = func() time.Time { return testNow }
	token, err := svc.IssueSessionToken(t.Context(), model.SessionTokenRequest{
		SessionID: "sess-1",
		UserID:    "user-1",
		Mode:      "owner",
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("expired", func(t *testing.T) {
		svc.now = func() time.Time { return testNow.Add(time.Minute + 6*time.Second) }
		resp := svc.ValidateSessionToken(t.Context(), model.TokenValidateRequest{
			SessionID: "sess-1",
			Token:     token.SessionToken,
		})
		if resp.Allowed || resp.Reason != "token expired" {
			t.Fatalf("ValidateSessionToken() = %#v, want expired rejection", resp)
		}
	})

	t.Run("tampered", func(t *testing.T) {
		svc.now = func() time.Time { return testNow }
		parts := strings.Split(token.SessionToken, ".")
		if len(parts) != 3 {
			t.Fatalf("token has %d segments, want 3", len(parts))
		}
		parts[1] = parts[1][:len(parts[1])-1] + "A"
		resp := svc.ValidateSessionToken(t.Context(), model.TokenValidateRequest{
			SessionID: "sess-1",
			Token:     strings.Join(parts, "."),
		})
		if resp.Allowed || resp.Reason != "invalid token" {
			t.Fatalf("ValidateSessionToken() = %#v, want invalid rejection", resp)
		}
	})
}

func TestValidateSessionTokenRejectsWrongSigningContext(t *testing.T) {
	issuer := New(testTokenConfig(), nil, nil)
	issuer.now = func() time.Time { return testNow }
	token, err := issuer.IssueSessionToken(t.Context(), model.SessionTokenRequest{
		SessionID: "sess-1",
		UserID:    "user-1",
		Mode:      "owner",
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		config TokenConfig
	}{
		{
			name: "wrong key",
			config: func() TokenConfig {
				cfg := testTokenConfig()
				cfg.SigningKey = []byte("abcdef0123456789abcdef0123456789")
				return cfg
			}(),
		},
		{
			name: "wrong issuer",
			config: func() TokenConfig {
				cfg := testTokenConfig()
				cfg.Issuer = "other-sts"
				return cfg
			}(),
		},
		{
			name: "wrong audience",
			config: func() TokenConfig {
				cfg := testTokenConfig()
				cfg.Audience = "other-session"
				return cfg
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier := New(test.config, nil, nil)
			verifier.now = func() time.Time { return testNow }
			resp := verifier.ValidateSessionToken(t.Context(), model.TokenValidateRequest{
				SessionID: "sess-1",
				Token:     token.SessionToken,
			})
			if resp.Allowed || resp.Reason != "invalid token" {
				t.Fatalf("ValidateSessionToken() = %#v, want invalid rejection", resp)
			}
		})
	}
}
