package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/sts/internal/model"
	"github.com/NUS-MTech-Capstone/sts/internal/service"
)

func newTestServer() *Server {
	svc := service.New(service.TokenConfig{
		TTL:           time.Minute,
		AutomationTTL: time.Minute,
		SigningKey:    []byte("0123456789abcdef0123456789abcdef"),
		Issuer:        "test-sts",
		Audience:      "test-session",
		ClockSkew:     5 * time.Second,
	}, nil, nil)
	return New(svc)
}

func TestValidateEndpointAllowsAndDeniesRequests(t *testing.T) {
	server := newTestServer()
	tests := []struct {
		name   string
		body   string
		status int
	}{
		{name: "allowed", body: `{"userId":"user-1","hostId":"host-1","crId":"cr-1","action":"start"}`, status: http.StatusOK},
		{name: "denied", body: `{"userId":"user-1","action":"delete"}`, status: http.StatusForbidden},
		{name: "bad json", body: `{`, status: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := doJSON(t, server, http.MethodPost, "/validate", tt.body, tt.status)
			if tt.status == http.StatusOK {
				var resp model.ValidateResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatal(err)
				}
				if !resp.Allowed {
					t.Fatalf("response = %#v", resp)
				}
			}
		})
	}
}

func TestTokenEndpointsReturnExpectedStatusCodes(t *testing.T) {
	server := newTestServer()

	doJSON(t, server, http.MethodPost, "/tokens/session", `{`, http.StatusBadRequest)
	doJSON(t, server, http.MethodPost, "/tokens/session", `{"sessionId":"sess-1"}`, http.StatusBadRequest)

	doJSON(t, server, http.MethodPost, "/tokens/validate", `{`, http.StatusBadRequest)
	doJSON(t, server, http.MethodPost, "/tokens/validate", `{"sessionId":"sess-1","token":"bad"}`, http.StatusForbidden)

	doJSON(t, server, http.MethodPost, "/tokens/automation", `{`, http.StatusBadRequest)
	automationReq := httptest.NewRequest(http.MethodPost, "/tokens/automation", strings.NewReader(`{"runId":"run-1","incidentId":"inc-1","hostId":"host-1","phase":"diagnose","allowedOperations":["health_check"],"ownerPodId":"pod-1","ownerInstanceId":"instance-1"}`))
	automationReq.Header.Set("Content-Type", "application/json")
	automationReq.Header.Set("Authorization", "Bearer workload")
	automationRec := httptest.NewRecorder()
	server.ServeHTTP(automationRec, automationReq)
	if automationRec.Code != http.StatusForbidden {
		t.Fatalf("automation status = %d, want %d", automationRec.Code, http.StatusForbidden)
	}

	doJSON(t, server, http.MethodPost, "/tokens/automation/validate", `{`, http.StatusBadRequest)
	doJSON(t, server, http.MethodPost, "/tokens/automation/validate", `{"runId":"run-1","token":"bad"}`, http.StatusForbidden)
}

func TestBearerToken(t *testing.T) {
	if got := bearerToken("Bearer token-1"); got != "token-1" {
		t.Fatalf("bearerToken() = %q", got)
	}
	if got := bearerToken("Basic token-1"); got != "" {
		t.Fatalf("bearerToken() = %q, want empty", got)
	}
}

func doJSON(t *testing.T, server *Server, method, path, body string, wantStatus int) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	server.ServeHTTP(rec, req)
	if rec.Code != wantStatus {
		t.Fatalf("%s %s status = %d, want %d body=%s", method, path, rec.Code, wantStatus, rec.Body.String())
	}
	return rec
}
