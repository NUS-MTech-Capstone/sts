package change_request

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetChangeRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/change-requests/cr-123" {
			t.Fatalf("path = %s, want /change-requests/cr-123", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"crId":"cr-123","status":"APPROVED"}`))
	}))
	defer server.Close()

	changeRequest, err := New(server.URL, time.Second).Get(t.Context(), "cr-123")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if changeRequest.CRID != "cr-123" {
		t.Fatalf("CRID = %q, want cr-123", changeRequest.CRID)
	}
}
