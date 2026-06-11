package service

import (
	"context"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/sts/internal/model"
)

func TestIssueAndValidateSessionToken(t *testing.T) {
	svc := New(time.Minute, nil, nil)
	ctx := context.Background()
	token, err := svc.IssueSessionToken(ctx, model.SessionTokenRequest{SessionID: "sess-1", UserID: "user-1", Mode: "owner"})
	if err != nil {
		t.Fatalf("IssueSessionToken() error = %v", err)
	}
	resp := svc.ValidateSessionToken(ctx, model.TokenValidateRequest{
		SessionID: "sess-1",
		UserID:    "user-1",
		Mode:      "owner",
		Token:     token.SessionToken,
	})
	if !resp.Allowed {
		t.Fatalf("ValidateSessionToken() allowed = false, reason = %s", resp.Reason)
	}
}

func TestValidateSessionTokenRejectsWrongUserOrMode(t *testing.T) {
	svc := New(time.Minute, nil, nil)
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
