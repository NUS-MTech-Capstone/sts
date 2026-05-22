package service

import (
	"context"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/sts/internal/model"
)

func TestIssueAndValidateSessionToken(t *testing.T) {
	svc := New(time.Minute)
	ctx := context.Background()
	token, err := svc.IssueSessionToken(ctx, model.SessionTokenRequest{SessionID: "sess-1", UserID: "user-1", Mode: "owner"})
	if err != nil {
		t.Fatalf("IssueSessionToken() error = %v", err)
	}
	resp := svc.ValidateSessionToken(ctx, model.TokenValidateRequest{SessionID: "sess-1", Token: token.SessionToken})
	if !resp.Allowed {
		t.Fatalf("ValidateSessionToken() allowed = false, reason = %s", resp.Reason)
	}
}
