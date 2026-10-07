package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/sts/internal/change_request"
	"github.com/NUS-MTech-Capstone/sts/internal/server_inventory"
	"github.com/NUS-MTech-Capstone/sts/internal/service"
)

// Use the real CR HTTP client and STS routes, bypassing browser filtering entirely.
func TestDirectAPITrustedCRContract(t *testing.T) {
	tests := []struct {
		name    string
		change  func(map[string]any)
		groups  any
		allowed bool
	}{
		{"valid", nil, []string{"Employee"}, true},
		{"admin", func(cr map[string]any) { cr["allowedRoles"] = []string{} }, []string{"Admin"}, true},
		{"expired", func(cr map[string]any) { cr["implementationEndAt"] = time.Now().Add(-time.Hour).Format(time.RFC3339) }, []string{"Admin"}, false},
		{"not yet valid", func(cr map[string]any) {
			cr["implementationStartAt"] = time.Now().Add(time.Minute).Format(time.RFC3339)
		}, []string{"Employee"}, false},
		{"unauthorized", nil, []string{"Auditor"}, false},
		{"missing actor", nil, nil, false},
		{"missing scope", func(cr map[string]any) { delete(cr, "hostIds") }, []string{"Admin"}, false},
		{"null scope", func(cr map[string]any) { cr["hostIds"] = nil }, []string{"Admin"}, false},
		{"empty scope", func(cr map[string]any) { cr["hostIds"] = []string{} }, []string{"Admin"}, false},
		{"blank scope", func(cr map[string]any) { cr["hostIds"] = []string{"host-1", " "} }, []string{"Admin"}, false},
		{"wrong host", func(cr map[string]any) { cr["hostIds"] = []string{"host-2"} }, []string{"Employee"}, false},
		{"wrong CR", func(cr map[string]any) { cr["crId"] = "other" }, []string{"Employee"}, false},
		{"malformed date", func(cr map[string]any) { cr["implementationStartAt"] = "invalid-secret-value" }, []string{"Employee"}, false},
		{"missing date", func(cr map[string]any) { delete(cr, "implementationStartAt") }, []string{"Employee"}, false},
		{"missing roles", func(cr map[string]any) { delete(cr, "allowedRoles") }, []string{"Admin"}, false},
		{"null roles", func(cr map[string]any) { cr["allowedRoles"] = nil }, []string{"Admin"}, false},
		{"empty roles", func(cr map[string]any) { cr["allowedRoles"] = []string{} }, []string{"Employee"}, false},
		{"malformed roles", func(cr map[string]any) { cr["allowedRoles"] = "Employee" }, []string{"Employee"}, false},
		{"upstream failure", nil, []string{"Employee"}, false},
	}
	inventory, err := server_inventory.NewStatic(`{"host-1":{"address":"test:22","username":"test","connectionType":"ssh","credentialSecretId":"test-key","hostPublicKey":"ssh-ed25519 TEST"}}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := map[string]any{"crId": "cr-1", "status": "Approved", "hostIds": []string{"host-1"}, "allowedRoles": []string{"Employee"}, "implementationStartAt": time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano), "implementationEndAt": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)}
			if tt.change != nil {
				tt.change(cr)
			}
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/change-requests/cr-1" || r.Header.Get("x-api-version") != "1" {
					t.Error("incorrect trusted lookup")
				}
				if tt.name == "upstream failure" {
					http.Error(w, "secret upstream diagnostic", 500)
					return
				}
				_ = json.NewEncoder(w).Encode(cr)
			}))
			defer upstream.Close()
			svc := service.New(service.TokenConfig{TTL: time.Minute, SigningKey: []byte("0123456789abcdef0123456789abcdef"), Issuer: "test", Audience: "test"}, change_request.New(upstream.URL, time.Second), inventory)
			server := httptest.NewServer(New(svc))
			defer server.Close()
			for _, action := range []string{"start", "rejoin", "observe"} {
				for _, path := range []string{"/validate", "/tokens/session"} {
					body := map[string]any{"userId": "user-1", "actorGroups": tt.groups, "crId": "cr-1", "hostId": "host-1", "sessionId": "sess-1", "action": action}
					if path == "/tokens/session" {
						body["mode"] = "owner"
						if action == "observe" {
							body["mode"] = "observer"
						}
					}
					data, _ := json.Marshal(body)
					req, _ := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(string(data)))
					req.Header.Set("x-api-version", "1")
					resp, err := server.Client().Do(req)
					if err != nil {
						t.Fatal(err)
					}
					var result map[string]any
					err = json.NewDecoder(resp.Body).Decode(&result)
					resp.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
					want := http.StatusForbidden
					if tt.allowed {
						want = http.StatusOK
						if path == "/tokens/session" {
							want = http.StatusCreated
						}
					}
					if resp.StatusCode != want {
						t.Fatalf("%s %s: status=%d want=%d", action, path, resp.StatusCode, want)
					}
					if !tt.allowed {
						if _, ok := result["sessionToken"]; ok {
							t.Fatal("denial returned token")
						}
						data, _ := json.Marshal(result)
						if strings.Contains(string(data), "secret") {
							t.Fatal("upstream secret leaked")
						}
					}
				}
			}
		})
	}
}
