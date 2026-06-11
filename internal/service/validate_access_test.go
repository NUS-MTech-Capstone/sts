package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/sts/internal/change_request"
	"github.com/NUS-MTech-Capstone/sts/internal/model"
	"github.com/NUS-MTech-Capstone/sts/internal/server_inventory"
)

type changeRequestStub struct {
	err error
}

func (s changeRequestStub) Get(context.Context, string) (change_request.ChangeRequest, error) {
	return change_request.ChangeRequest{}, s.err
}

type serverInventoryStub struct {
	err error
}

func (s serverInventoryStub) Get(context.Context, string) (server_inventory.Server, error) {
	return server_inventory.Server{}, s.err
}

func TestValidateAccessChecksConfiguredUpstreams(t *testing.T) {
	svc := New(
		time.Minute,
		changeRequestStub{},
		serverInventoryStub{err: errors.New("host not found")},
	)

	resp := svc.ValidateAccess(context.Background(), model.ValidateRequest{
		UserID: "user-1",
		HostID: "host-1",
		CRID:   "cr-1",
		Action: "start",
	})

	if resp.Allowed {
		t.Fatal("Allowed = true, want false")
	}
	if !strings.Contains(resp.Reason, "host not found") {
		t.Fatalf("Reason = %q, want host lookup error", resp.Reason)
	}
}
