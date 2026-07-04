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
	if req.UserID == "" {
		return "userId is required"
	}
	return ""
}

type startAccessPolicy struct{}

func (startAccessPolicy) Validate(ctx context.Context, svc *Service, req model.ValidateRequest) string {
	if req.HostID == "" || req.CRID == "" {
		return "hostId and crId are required for start"
	}
	if svc.changeRequests != nil {
		changeRequest, err := svc.changeRequests.Get(ctx, req.CRID)
		if err != nil {
			return err.Error()
		}
		if !strings.EqualFold(changeRequest.Status, "approved") {
			return "change request is not approved"
		}
		if len(changeRequest.HostIDs) > 0 && !contains(changeRequest.HostIDs, req.HostID) {
			return "change request does not cover host"
		}
	}
	if svc.serverInventory != nil {
		if _, err := svc.serverInventory.Get(ctx, req.HostID); err != nil {
			return err.Error()
		}
	}
	return ""
}

type rejoinAccessPolicy struct{}

func (rejoinAccessPolicy) Validate(_ context.Context, _ *Service, req model.ValidateRequest) string {
	if req.SessionID == "" && (req.HostID == "" || req.CRID == "") {
		return "sessionId or hostId and crId are required for rejoin"
	}
	return ""
}

type observeAccessPolicy struct{}

func (observeAccessPolicy) Validate(_ context.Context, _ *Service, req model.ValidateRequest) string {
	if req.SessionID == "" {
		return "sessionId is required"
	}
	return ""
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
