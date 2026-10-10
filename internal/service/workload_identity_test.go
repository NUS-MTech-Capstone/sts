package service

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type identityValidatorFunc func(context.Context, string) (string, error)

func (f identityValidatorFunc) Validate(ctx context.Context, token string) (string, error) {
	return f(ctx, token)
}

func TestValidateWorkloadIdentityBoundary(t *testing.T) {
	for _, tc := range []struct {
		name         string
		configured   bool
		validatorErr error
		want         string
	}{
		{"not configured", false, nil, "not configured"},
		{"denied", true, errors.New("internal sensitive validator detail"), "not authorized"},
		{"cancelled", true, context.Canceled, "not authorized"},
		{"allowed", true, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			svc := New(TokenConfig{}, nil, nil)
			ctx := t.Context()
			if tc.configured {
				svc = New(TokenConfig{}, nil, nil, nil, identityValidatorFunc(func(got context.Context, token string) (string, error) {
					calls++
					if got != ctx || token != "opaque-test-token" {
						t.Error("validation context or token changed")
					}
					return "system:serviceaccount:dendenmushi-agentic:agent-controlplane", tc.validatorErr
				}))
			}
			subject, err := svc.ValidateWorkloadIdentity(ctx, "opaque-test-token")
			if tc.want == "" {
				if err != nil || subject != "system:serviceaccount:dendenmushi-agentic:agent-controlplane" {
					t.Fatalf("subject=%q err=%v", subject, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "sensitive") || subject != "" {
				t.Fatalf("subject=%q err=%v", subject, err)
			}
			if tc.configured && calls != 1 {
				t.Fatalf("validator calls=%d", calls)
			}
		})
	}
}
