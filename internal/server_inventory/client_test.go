package server_inventory

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/servers/host-123" {
			t.Fatalf("path = %s, want /servers/host-123", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hostId":"host-123","status":"READY"}`))
	}))
	defer server.Close()

	host, err := New(server.URL, time.Second).Get(t.Context(), "host-123")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if host.HostID != "host-123" {
		t.Fatalf("HostID = %q, want host-123", host.HostID)
	}
}
