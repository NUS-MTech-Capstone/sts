package service

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/sts/internal/change_request"
	"github.com/NUS-MTech-Capstone/sts/internal/model"
)

func TestChangeRequestPolicyAllAttachmentActionsAndIssuance(t *testing.T) {
	tests := []struct {
		name   string
		change func(*change_request.ChangeRequest, *model.ValidateRequest)
		want   string
	}{
		{"valid", func(*change_request.ChangeRequest, *model.ValidateRequest) {}, ""},
		{"exact start", func(cr *change_request.ChangeRequest, _ *model.ValidateRequest) { cr.ImplementationStartAt = testNow }, ""},
		{"exact end", func(cr *change_request.ChangeRequest, _ *model.ValidateRequest) { cr.ImplementationEndAt = testNow }, "expired"},
		{"future", func(cr *change_request.ChangeRequest, _ *model.ValidateRequest) {
			cr.ImplementationStartAt = testNow.Add(time.Nanosecond)
		}, "not yet valid"},
		{"expired", func(cr *change_request.ChangeRequest, _ *model.ValidateRequest) {
			cr.ImplementationEndAt = testNow.Add(-time.Nanosecond)
		}, "expired"},
		{"missing start", func(cr *change_request.ChangeRequest, _ *model.ValidateRequest) {
			cr.ImplementationStartAt = time.Time{}
		}, "window is invalid"},
		{"missing end", func(cr *change_request.ChangeRequest, _ *model.ValidateRequest) { cr.ImplementationEndAt = time.Time{} }, "window is invalid"},
		{"reversed window", func(cr *change_request.ChangeRequest, _ *model.ValidateRequest) {
			cr.ImplementationEndAt = cr.ImplementationStartAt.Add(-time.Second)
		}, "window is invalid"},
		{"zero window", func(cr *change_request.ChangeRequest, _ *model.ValidateRequest) {
			cr.ImplementationEndAt = cr.ImplementationStartAt
		}, "window is invalid"},
		{"wrong CR", func(cr *change_request.ChangeRequest, _ *model.ValidateRequest) { cr.CRID = "other" }, "ID mismatch"},
		{"unapproved", func(cr *change_request.ChangeRequest, _ *model.ValidateRequest) { cr.Status = "Pending" }, "not approved"},
		{"missing scope", func(cr *change_request.ChangeRequest, _ *model.ValidateRequest) { cr.HostIDs = nil }, "scope"},
		{"empty scope", func(cr *change_request.ChangeRequest, _ *model.ValidateRequest) { cr.HostIDs = []string{} }, "scope"},
		{"blank entry with valid host", func(cr *change_request.ChangeRequest, _ *model.ValidateRequest) { cr.HostIDs = append(cr.HostIDs, " ") }, "scope"},
		{"wrong host", func(cr *change_request.ChangeRequest, _ *model.ValidateRequest) { cr.HostIDs = []string{"other"} }, "does not cover host"},
		{"unauthorized", func(_ *change_request.ChangeRequest, r *model.ValidateRequest) { r.ActorGroups = []string{"Auditor"} }, "not entitled"},
		{"case sensitive", func(_ *change_request.ChangeRequest, r *model.ValidateRequest) { r.ActorGroups = []string{"employee"} }, "not entitled"},
		{"missing actor", func(_ *change_request.ChangeRequest, r *model.ValidateRequest) { r.ActorGroups = nil }, "actor groups"},
		{"blank actor group", func(_ *change_request.ChangeRequest, r *model.ValidateRequest) {
			r.ActorGroups = []string{"Admin", " "}
		}, "actor groups"},
		{"no groups", func(_ *change_request.ChangeRequest, r *model.ValidateRequest) { r.ActorGroups = []string{} }, "not entitled"},
		{"empty roles", func(cr *change_request.ChangeRequest, _ *model.ValidateRequest) { cr.AllowedRoles = []string{} }, "not entitled"},
		{"admin role bypass", func(cr *change_request.ChangeRequest, r *model.ValidateRequest) {
			cr.AllowedRoles = []string{}
			r.ActorGroups = []string{"Admin"}
		}, ""},
		{"admin cannot bypass missing roles", func(cr *change_request.ChangeRequest, r *model.ValidateRequest) {
			cr.AllowedRoles = nil
			r.ActorGroups = []string{"Admin"}
		}, "roles are missing"},
		{"admin cannot bypass window", func(cr *change_request.ChangeRequest, r *model.ValidateRequest) {
			cr.ImplementationEndAt = testNow
			r.ActorGroups = []string{"Admin"}
		}, "expired"},
		{"admin cannot bypass scope", func(cr *change_request.ChangeRequest, r *model.ValidateRequest) {
			cr.HostIDs = nil
			r.ActorGroups = []string{"Admin"}
		}, "scope"},
		{"admin cannot bypass host", func(cr *change_request.ChangeRequest, r *model.ValidateRequest) {
			cr.HostIDs = []string{"other"}
			r.ActorGroups = []string{"Admin"}
		}, "does not cover host"},
		{"admin cannot bypass approval", func(cr *change_request.ChangeRequest, r *model.ValidateRequest) {
			cr.Status = "Pending"
			r.ActorGroups = []string{"Admin"}
		}, "not approved"},
	}
	for _, action := range []string{"start", "rejoin", "observe"} {
		for _, tt := range tests {
			t.Run(action+"/"+tt.name, func(t *testing.T) {
				cr := validChangeRequest()
				req := model.ValidateRequest{UserID: "user-1", ActorGroups: []string{"Employee"}, HostID: "host-1", CRID: "cr-1", SessionID: "sess-1", Action: action}
				tt.change(&cr, &req)
				svc := New(testTokenConfig(), changeRequestStub{changeRequest: cr}, testInventory())
				svc.now = func() time.Time { return testNow }
				resp := svc.ValidateAccess(t.Context(), req)
				if resp.Allowed != (tt.want == "") || !strings.Contains(resp.Reason, tt.want) {
					t.Fatalf("allowed=%v reason=%q want=%q", resp.Allowed, resp.Reason, tt.want)
				}
				mode := "owner"
				if action == "observe" {
					mode = "observer"
				}
				token, err := svc.IssueSessionToken(t.Context(), model.SessionTokenRequest{UserID: req.UserID, ActorGroups: req.ActorGroups, HostID: req.HostID, CRID: req.CRID, SessionID: req.SessionID, Action: action, Mode: mode})
				if tt.want == "" {
					if err != nil || token.SessionToken == "" {
						t.Fatalf("valid issuance failed: %v", err)
					}
				} else if !errors.Is(err, ErrAccessDenied) || token.SessionToken != "" {
					t.Fatalf("invalid issuance returned token or wrong error: %v", err)
				}
				if action == "rejoin" {
					req.SessionID = ""
					if got := svc.ValidateAccess(t.Context(), req); got.Allowed != resp.Allowed {
						t.Fatal("discovery policy diverged")
					}
				}
			})
		}
	}
}

func TestCRPolicyFailsClosedWithoutTrustedUpstream(t *testing.T) {
	for _, client := range []ChangeRequestClient{nil, changeRequestStub{err: errors.New("secret upstream diagnostic")}} {
		svc := New(testTokenConfig(), client, testInventory())
		req := model.ValidateRequest{UserID: "user-1", ActorGroups: []string{"Admin"}, HostID: "host-1", CRID: "cr-1", Action: "start"}
		resp := svc.ValidateAccess(t.Context(), req)
		if resp.Allowed || strings.Contains(resp.Reason, "secret") {
			t.Fatal("upstream failure allowed or leaked")
		}
	}
}
