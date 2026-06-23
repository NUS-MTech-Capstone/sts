package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/sts/internal/model"
	"github.com/NUS-MTech-Capstone/sts/internal/server_inventory"
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

func testInventory() ServerInventoryClient {
	return serverInventoryStub{server: server_inventory.Server{
		HostID: "host-1", Address: "server.example:22", Username: "ubuntu",
		ConnectionType: "ssh", CredentialSecretID: "secret/host-1",
		HostPublicKey: "ssh-ed25519 AAAATEST",
		Automation: server_inventory.AutomationProfile{
			ServiceName: "myapp", HealthURL: "http://127.0.0.1:8080/healthz",
			HelperPath:        "/usr/local/sbin/ddm-ops",
			AllowedOperations: []string{"service_status", "health_check", "restart_service"},
		},
	}}
}

type workloadStub struct{}

func (workloadStub) Validate(context.Context, string) (string, error) {
	return "system:serviceaccount:dendenmushi:incident-agent", nil
}

func testTokenRequest(action, mode string) model.SessionTokenRequest {
	return model.SessionTokenRequest{
		SessionID: "sess-1", UserID: "user-1", HostID: "host-1", CRID: "cr-1",
		ConnectionType: "ssh", Action: action, Mode: mode,
	}
}

func TestIssueAndValidateAutomationToken(t *testing.T) {
	svc := New(testTokenConfig(), nil, testInventory(), workloadStub{})
	svc.now = func() time.Time { return testNow }
	token, err := svc.IssueAutomationToken(t.Context(), "workload-token", model.AutomationTokenRequest{
		RunID: "run-1", IncidentID: "inc-1", HostID: "host-1", Phase: "remediate",
		AllowedOperations: []string{"restart_service"}, PlanHash: "plan-hash",
		OwnerPodID: "pod-1", OwnerInstanceID: "instance-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	resp := svc.ValidateAutomationToken(t.Context(), model.AutomationTokenValidateRequest{
		RunID: "run-1", Token: token.CapabilityToken,
	})
	if !resp.Allowed || resp.Claims == nil {
		t.Fatalf("validation = %#v", resp)
	}
	if resp.Claims.PlanHash != "plan-hash" || resp.Claims.HelperPath != "/usr/local/sbin/ddm-ops" {
		t.Fatalf("claims = %#v", resp.Claims)
	}
	sessionResp := svc.ValidateSessionToken(t.Context(), model.TokenValidateRequest{
		SessionID: "run-1", Token: token.CapabilityToken,
	})
	if sessionResp.Allowed {
		t.Fatal("automation token was accepted as a session token")
	}
}

func TestIssueAutomationTokenRejectsUnapprovedOperation(t *testing.T) {
	svc := New(testTokenConfig(), nil, testInventory(), workloadStub{})
	_, err := svc.IssueAutomationToken(t.Context(), "workload-token", model.AutomationTokenRequest{
		RunID: "run-1", IncidentID: "inc-1", HostID: "host-1", Phase: "diagnose",
		AllowedOperations: []string{"arbitrary_shell"}, OwnerPodID: "pod-1", OwnerInstanceID: "instance-1",
	})
	if err == nil {
		t.Fatal("unapproved operation was accepted")
	}
}

func TestValidateAutomationTokenRejectsExpiredAndWrongRun(t *testing.T) {
	svc := New(testTokenConfig(), nil, testInventory(), workloadStub{})
	svc.now = func() time.Time { return testNow }
	token, err := svc.IssueAutomationToken(t.Context(), "workload-token", model.AutomationTokenRequest{
		RunID: "run-1", IncidentID: "inc-1", HostID: "host-1", Phase: "verify",
		AllowedOperations: []string{"health_check"},
		OwnerPodID:        "pod-1", OwnerInstanceID: "instance-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp := svc.ValidateAutomationToken(t.Context(), model.AutomationTokenValidateRequest{
		RunID: "run-2", Token: token.CapabilityToken,
	}); resp.Allowed {
		t.Fatal("automation token was accepted for the wrong run")
	}
	svc.now = func() time.Time { return testNow.Add(time.Minute + 6*time.Second) }
	if resp := svc.ValidateAutomationToken(t.Context(), model.AutomationTokenValidateRequest{
		RunID: "run-1", Token: token.CapabilityToken,
	}); resp.Allowed {
		t.Fatal("expired automation token was accepted")
	}
}

func TestIssueAndValidateSessionToken(t *testing.T) {
	svc := New(testTokenConfig(), nil, testInventory())
	svc.now = func() time.Time { return testNow }
	ctx := context.Background()
	token, err := svc.IssueSessionToken(ctx, testTokenRequest("start", "owner"))
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
	verifier := New(testTokenConfig(), nil, testInventory())
	verifier.now = func() time.Time { return testNow }
	resp := verifier.ValidateSessionToken(ctx, model.TokenValidateRequest{
		SessionID: "sess-1",
		UserID:    "user-1",
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
		claims.SessionID != "sess-1" || claims.Mode != "owner" || claims.Action != "start" ||
		claims.HostID != "host-1" || claims.CRID != "cr-1" || claims.ConnectionType != "ssh" ||
		claims.Address != "server.example:22" || claims.Username != "ubuntu" ||
		claims.ExpiresAt == nil || claims.IssuedAt == nil || claims.NotBefore == nil || claims.ID == "" {
		t.Fatalf("unexpected claims: %#v", claims)
	}
}

func TestValidateSessionTokenRejectsWrongUser(t *testing.T) {
	svc := New(testTokenConfig(), nil, testInventory())
	svc.now = func() time.Time { return testNow }
	token, err := svc.IssueSessionToken(t.Context(), testTokenRequest("observe", "observer"))
	if err != nil {
		t.Fatal(err)
	}

	resp := svc.ValidateSessionToken(t.Context(), model.TokenValidateRequest{
		SessionID: "sess-1", UserID: "other-user", Token: token.SessionToken,
	})
	if resp.Allowed {
		t.Fatal("ValidateSessionToken() allowed mismatched user")
	}
}

func TestIssueAndValidateRejoinOwnerSessionToken(t *testing.T) {
	svc := New(testTokenConfig(), nil, testInventory())
	svc.now = func() time.Time { return testNow }

	token, err := svc.IssueSessionToken(t.Context(), testTokenRequest("rejoin", "owner"))
	if err != nil {
		t.Fatalf("IssueSessionToken() error = %v", err)
	}

	resp := svc.ValidateSessionToken(t.Context(), model.TokenValidateRequest{
		SessionID: "sess-1",
		UserID:    "user-1",
		Token:     token.SessionToken,
	})
	if !resp.Allowed || resp.Claims == nil {
		t.Fatalf("ValidateSessionToken() = %#v, want allowed rejoin owner claims", resp)
	}
	if resp.Claims.Action != "rejoin" || resp.Claims.Mode != "owner" {
		t.Fatalf("claims action/mode = %s/%s, want rejoin/owner", resp.Claims.Action, resp.Claims.Mode)
	}
}

func TestIssueAndValidateObserveSessionToken(t *testing.T) {
	svc := New(testTokenConfig(), nil, testInventory())
	svc.now = func() time.Time { return testNow }

	token, err := svc.IssueSessionToken(t.Context(), testTokenRequest("observe", "observer"))
	if err != nil {
		t.Fatalf("IssueSessionToken() error = %v", err)
	}

	resp := svc.ValidateSessionToken(t.Context(), model.TokenValidateRequest{
		SessionID: "sess-1",
		UserID:    "user-1",
		Token:     token.SessionToken,
	})
	if !resp.Allowed || resp.Claims == nil {
		t.Fatalf("ValidateSessionToken() = %#v, want allowed observe observer claims", resp)
	}
	if resp.Claims.Action != "observe" || resp.Claims.Mode != "observer" {
		t.Fatalf("claims action/mode = %s/%s, want observe/observer", resp.Claims.Action, resp.Claims.Mode)
	}
}

func TestIssueSessionTokenRejectsInvalidActionMode(t *testing.T) {
	svc := New(testTokenConfig(), nil, testInventory())
	if _, err := svc.IssueSessionToken(t.Context(), testTokenRequest("observe", "owner")); err == nil {
		t.Fatal("IssueSessionToken() accepted observe owner token")
	}
	if _, err := svc.IssueSessionToken(t.Context(), testTokenRequest("rejoin", "observer")); err == nil {
		t.Fatal("IssueSessionToken() accepted rejoin observer token")
	}
	if _, err := svc.IssueSessionToken(t.Context(), testTokenRequest("start", "observer")); err == nil {
		t.Fatal("IssueSessionToken() accepted start observer token")
	}
}

func TestValidateSessionTokenRejectsExpiredOrTamperedJWT(t *testing.T) {
	svc := New(testTokenConfig(), nil, testInventory())
	svc.now = func() time.Time { return testNow }
	token, err := svc.IssueSessionToken(t.Context(), testTokenRequest("start", "owner"))
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
	issuer := New(testTokenConfig(), nil, testInventory())
	issuer.now = func() time.Time { return testNow }
	token, err := issuer.IssueSessionToken(t.Context(), testTokenRequest("start", "owner"))
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
			verifier := New(test.config, nil, testInventory())
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
