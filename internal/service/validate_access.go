package service

import (
	"context"
	"strings"

	"github.com/NUS-MTech-Capstone/sts/internal/model"
)

func (s *Service) ValidateAccess(ctx context.Context, req model.ValidateRequest) model.ValidateResponse {
	commonPolicy := commonAccessPolicy{}
	if reason := commonPolicy.Validate(ctx, s, req); reason != "" {
		return deny(reason)
	}
	policy, ok := s.accessPolicy(req.Action)
	if !ok {
		return deny("action must be start, rejoin, observe or stop")
	}
	if reason := policy.Validate(ctx, s, req); reason != "" {
		return deny(reason)
	}
	return model.ValidateResponse{Allowed: true}
}

type accessPolicy interface {
	Validate(context.Context, *Service, model.ValidateRequest) string
}

type commonAccessPolicy struct{}

func (commonAccessPolicy) Validate(_ context.Context, _ *Service, req model.ValidateRequest) string {
	if strings.TrimSpace(req.UserID) == "" {
		return "userId is required"
	}
	return ""
}

type startAccessPolicy struct{}

func (startAccessPolicy) Validate(ctx context.Context, svc *Service, req model.ValidateRequest) string {
	if req.HostID == "" || req.CRID == "" {
		return "hostId and crId are required for start"
	}
	if reason := svc.validateChangeRequest(ctx, req); reason != "" {
		return reason
	}
	if svc.serverInventory != nil {
		if _, err := svc.serverInventory.Get(ctx, req.HostID); err != nil {
			return "server inventory lookup failed"
		}
	}
	return ""
}

type rejoinAccessPolicy struct{}

func (rejoinAccessPolicy) Validate(ctx context.Context, svc *Service, req model.ValidateRequest) string {
	if req.SessionID == "" && (req.HostID == "" || req.CRID == "") {
		return "sessionId or hostId and crId are required for rejoin"
	}
	return svc.validateChangeRequest(ctx, req)
}

type observeAccessPolicy struct{}

func (observeAccessPolicy) Validate(ctx context.Context, svc *Service, req model.ValidateRequest) string {
	if req.SessionID == "" {
		return "sessionId is required"
	}
	return svc.validateChangeRequest(ctx, req)
}

type stopAccessPolicy struct{}

func (stopAccessPolicy) Validate(_ context.Context, _ *Service, req model.ValidateRequest) string {
	if req.SessionID == "" {
		return "sessionId is required for stop"
	}
	return ""
}

func (s *Service) accessPolicy(action string) (accessPolicy, bool) {
	switch action {
	case "start":
		return startAccessPolicy{}, true
	case "rejoin":
		return rejoinAccessPolicy{}, true
	case "observe":
		return observeAccessPolicy{}, true
	case "stop":
		return stopAccessPolicy{}, true
	default:
		return nil, false
	}
}

func deny(reason string) model.ValidateResponse {
	return model.ValidateResponse{Allowed: false, Reason: reason}
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// Role names follow the web application's case-insensitive Cognito role mapping.
// Resource identifiers still use exact matching through contains.
func containsRole(groups []string, role string) bool {
	for _, group := range groups {
		if strings.EqualFold(group, role) {
			return true
		}
	}
	return false
}

// validateChangeRequest is shared by access validation and token issuance.
// ActorGroups are assertions from the trusted control plane, never browser input.
func (s *Service) validateChangeRequest(ctx context.Context, req model.ValidateRequest) string {
	if strings.TrimSpace(req.HostID) == "" || strings.TrimSpace(req.CRID) == "" {
		return "hostId and crId are required"
	}
	if req.ActorGroups == nil || invalidEntries(req.ActorGroups) {
		return "actor groups are required and must be valid"
	}
	if s.changeRequests == nil {
		return "change request validation is not configured"
	}
	cr, err := s.changeRequests.Get(ctx, req.CRID)
	if err != nil {
		return "change request lookup failed"
	}
	if cr.CRID != req.CRID {
		return "change request ID mismatch"
	}
	if !strings.EqualFold(cr.Status, "approved") {
		return "change request is not approved"
	}
	if cr.ImplementationStartAt.IsZero() || cr.ImplementationEndAt.IsZero() || !cr.ImplementationStartAt.Before(cr.ImplementationEndAt) {
		return "change request window is invalid"
	}
	now := s.now()
	if now.Before(cr.ImplementationStartAt) {
		return "change request is not yet valid"
	}
	if !now.Before(cr.ImplementationEndAt) {
		return "change request has expired"
	}
	if len(cr.HostIDs) == 0 || invalidEntries(cr.HostIDs) {
		return "change request host scope is required and must be non-empty"
	}
	if !contains(cr.HostIDs, req.HostID) {
		return "change request does not cover host"
	}
	if cr.AllowedRoles == nil || invalidEntries(cr.AllowedRoles) {
		return "change request roles are missing or invalid"
	}
	if containsRole(req.ActorGroups, "Admin") {
		return ""
	}
	for _, role := range cr.AllowedRoles {
		if containsRole(req.ActorGroups, role) {
			return ""
		}
	}
	return "actor is not entitled to change request"
}

func invalidEntries(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value {
			return true
		}
	}
	return false
}
