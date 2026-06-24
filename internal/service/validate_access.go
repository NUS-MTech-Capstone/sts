package service

import (
	"context"
	"strings"

	"github.com/NUS-MTech-Capstone/sts/internal/model"
)

func (s *Service) ValidateAccess(ctx context.Context, req model.ValidateRequest) model.ValidateResponse {
	if req.UserID == "" {
		return model.ValidateResponse{Allowed: false, Reason: "userId is required"}
	}
	if req.Action != "start" && req.Action != "rejoin" && req.Action != "observe" && req.Action != "stop" {
		return model.ValidateResponse{Allowed: false, Reason: "action must be start, rejoin, observe or stop"}
	}
	if req.Action == "start" && (req.HostID == "" || req.CRID == "") {
		return model.ValidateResponse{Allowed: false, Reason: "hostId and crId are required for start"}
	}
	if req.Action == "start" && s.changeRequests != nil {
		changeRequest, err := s.changeRequests.Get(ctx, req.CRID)
		if err != nil {
			return model.ValidateResponse{Allowed: false, Reason: err.Error()}
		}
		if !strings.EqualFold(changeRequest.Status, "approved") {
			return model.ValidateResponse{Allowed: false, Reason: "change request is not approved"}
		}
		if len(changeRequest.HostIDs) > 0 && !contains(changeRequest.HostIDs, req.HostID) {
			return model.ValidateResponse{Allowed: false, Reason: "change request does not cover host"}
		}
	}
	if req.Action == "start" && s.serverInventory != nil {
		if _, err := s.serverInventory.Get(ctx, req.HostID); err != nil {
			return model.ValidateResponse{Allowed: false, Reason: err.Error()}
		}
	}
	if req.Action == "rejoin" && req.SessionID == "" && (req.HostID == "" || req.CRID == "") {
		return model.ValidateResponse{Allowed: false, Reason: "sessionId or hostId and crId are required for rejoin"}
	}
	if req.Action == "observe" && req.SessionID == "" {
		return model.ValidateResponse{Allowed: false, Reason: "sessionId is required"}
	}
	if req.Action == "stop" && req.SessionID == "" {
		return model.ValidateResponse{Allowed: false, Reason: "sessionId is required for stop"}
	}
	return model.ValidateResponse{Allowed: true}
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
