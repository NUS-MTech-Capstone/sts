package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/sts/internal/change_request"
	"github.com/NUS-MTech-Capstone/sts/internal/model"
	"github.com/NUS-MTech-Capstone/sts/internal/server_inventory"
)

type changeRequestStub struct {
	changeRequest change_request.ChangeRequest
	err           error
}

func (s changeRequestStub) Get(context.Context, string) (change_request.ChangeRequest, error) {
	if s.err != nil {
		return change_request.ChangeRequest{}, s.err
	}
	if s.changeRequest.CRID == "" {
		return validChangeRequest(), nil
	}
	return s.changeRequest, nil
}

type serverInventoryStub struct {
	server server_inventory.Server
	err    error
}

func (s serverInventoryStub) Get(context.Context, string) (server_inventory.Server, error) {
	return s.server, s.err
}

func TestValidateAccessChecksConfiguredUpstreams(t *testing.T) {
	svc := New(
		TokenConfig{TTL: time.Minute},
		changeRequestStub{},
		serverInventoryStub{err: errors.New("host not found")},
	)

	resp := svc.ValidateAccess(context.Background(), model.ValidateRequest{ActorGroups: []string{"Employee"},
		UserID: "user-1",
		HostID: "host-1",
		CRID:   "cr-1",
		Action: "start",
	})

	if resp.Allowed {
		t.Fatal("Allowed = true, want false")
	}
	if !strings.Contains(resp.Reason, "server inventory lookup failed") {
		t.Fatalf("Reason = %q, want host lookup error", resp.Reason)
	}
}

func TestValidateAccessRejectsUnapprovedChangeRequest(t *testing.T) {
	svc := New(
		TokenConfig{TTL: time.Minute},
		changeRequestStub{changeRequest: change_request.ChangeRequest{CRID: "cr-1", Status: "Pending"}},
		serverInventoryStub{},
	)

	resp := svc.ValidateAccess(context.Background(), model.ValidateRequest{ActorGroups: []string{"Employee"},
		UserID: "user-1",
		HostID: "host-1",
		CRID:   "cr-1",
		Action: "start",
	})

	if resp.Allowed {
		t.Fatal("Allowed = true, want false")
	}
	if !strings.Contains(resp.Reason, "not approved") {
		t.Fatalf("Reason = %q, want not approved", resp.Reason)
	}
}

func TestValidateAccessRejectsChangeRequestHostMismatch(t *testing.T) {
	svc := New(
		TokenConfig{TTL: time.Minute},
		changeRequestStub{changeRequest: change_request.ChangeRequest{
			CRID: "cr-1", Status: "Approved", HostIDs: []string{"host-2"},
			ImplementationStartAt: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), ImplementationEndAt: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), AllowedRoles: []string{"Employee"},
		}},
		serverInventoryStub{},
	)

	resp := svc.ValidateAccess(context.Background(), model.ValidateRequest{ActorGroups: []string{"Employee"},
		UserID: "user-1",
		HostID: "host-1",
		CRID:   "cr-1",
		Action: "start",
	})

	if resp.Allowed {
		t.Fatal("Allowed = true, want false")
	}
	if !strings.Contains(resp.Reason, "does not cover host") {
		t.Fatalf("Reason = %q, want host scope denial", resp.Reason)
	}
}

func TestValidateAccessRejectsUnknownAction(t *testing.T) {
	svc := New(TokenConfig{TTL: time.Minute}, changeRequestStub{}, nil)

	resp := svc.ValidateAccess(context.Background(), model.ValidateRequest{ActorGroups: []string{"Employee"},
		UserID: "user-1",
		Action: "delete",
	})

	if resp.Allowed {
		t.Fatal("Allowed = true, want false")
	}
	if !strings.Contains(resp.Reason, "action") {
		t.Fatalf("Reason = %q, want action validation error", resp.Reason)
	}
}

func TestValidateAccessAllowsRejoinDiscoveryByHostAndCR(t *testing.T) {
	svc := New(TokenConfig{TTL: time.Minute}, changeRequestStub{}, nil)

	resp := svc.ValidateAccess(context.Background(), model.ValidateRequest{ActorGroups: []string{"Employee"},
		UserID: "user-1",
		HostID: "host-1",
		CRID:   "cr-1",
		Action: "rejoin",
	})

	if !resp.Allowed {
		t.Fatalf("Allowed = false, reason = %q", resp.Reason)
	}
}

func TestValidateAccessRejectsRejoinWithoutSessionOrDiscoveryScope(t *testing.T) {
	svc := New(TokenConfig{TTL: time.Minute}, changeRequestStub{}, nil)

	resp := svc.ValidateAccess(context.Background(), model.ValidateRequest{ActorGroups: []string{"Employee"},
		UserID: "user-1",
		Action: "rejoin",
	})

	if resp.Allowed {
		t.Fatal("Allowed = true, want false")
	}
	if !strings.Contains(resp.Reason, "sessionId") {
		t.Fatalf("Reason = %q, want sessionId validation error", resp.Reason)
	}
}

func TestValidateAccessAllowsObserveForEntitledActors(t *testing.T) {
	svc := New(TokenConfig{TTL: time.Minute}, changeRequestStub{}, nil)

	for _, userID := range []string{"owner-user", "observer-user"} {
		resp := svc.ValidateAccess(context.Background(), model.ValidateRequest{ActorGroups: []string{"Employee"},
			UserID:    userID,
			SessionID: "sess-1", HostID: "host-1", CRID: "cr-1",
			Action: "observe",
		})

		if !resp.Allowed {
			t.Fatalf("ValidateAccess(%q) allowed = false, reason = %q", userID, resp.Reason)
		}
	}
}

func TestValidateAccessRejectsObserveWithoutSession(t *testing.T) {
	svc := New(TokenConfig{TTL: time.Minute}, changeRequestStub{}, nil)

	resp := svc.ValidateAccess(context.Background(), model.ValidateRequest{ActorGroups: []string{"Employee"},
		UserID: "observer-user",
		Action: "observe",
	})

	if resp.Allowed {
		t.Fatal("Allowed = true, want false")
	}
	if !strings.Contains(resp.Reason, "sessionId") {
		t.Fatalf("Reason = %q, want sessionId validation error", resp.Reason)
	}
}

func TestValidateAccessRequiresSessionIdForStop(t *testing.T) {
	svc := New(TokenConfig{TTL: time.Minute}, changeRequestStub{}, nil)

	resp := svc.ValidateAccess(context.Background(), model.ValidateRequest{ActorGroups: []string{"Employee"},
		UserID: "user-1",
		Action: "stop",
	})

	if resp.Allowed {
		t.Fatal("Allowed = true, want false")
	}
	if !strings.Contains(resp.Reason, "sessionId") {
		t.Fatalf("Reason = %q, want sessionId validation error", resp.Reason)
	}
}

func TestValidateAccessAllowsStopWithSessionId(t *testing.T) {
	svc := New(TokenConfig{TTL: time.Minute}, changeRequestStub{}, nil)

	resp := svc.ValidateAccess(context.Background(), model.ValidateRequest{ActorGroups: []string{"Employee"},
		UserID:    "user-1",
		SessionID: "sess-1",
		Action:    "stop",
	})

	if !resp.Allowed {
		t.Fatalf("Allowed = false, reason = %q", resp.Reason)
	}
}

func TestAccessPolicySelection(t *testing.T) {
	svc := New(TokenConfig{TTL: time.Minute}, changeRequestStub{}, nil)

	tests := []struct {
		action string
		want   accessPolicy
	}{
		{action: "start", want: startAccessPolicy{}},
		{action: "rejoin", want: rejoinAccessPolicy{}},
		{action: "observe", want: observeAccessPolicy{}},
		{action: "stop", want: stopAccessPolicy{}},
	}
	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			policy, ok := svc.accessPolicy(tt.action)
			if !ok {
				t.Fatal("accessPolicy() ok = false")
			}
			if fmt.Sprintf("%T", policy) != fmt.Sprintf("%T", tt.want) {
				t.Fatalf("accessPolicy() = %T, want %T", policy, tt.want)
			}
		})
	}
}

func validChangeRequest() change_request.ChangeRequest {
	return change_request.ChangeRequest{CRID: "cr-1", Status: "Approved", HostIDs: []string{"host-1"}, AllowedRoles: []string{"Employee"}, ImplementationStartAt: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), ImplementationEndAt: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)}
}
