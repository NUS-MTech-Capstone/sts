package service

import (
	"context"

	"github.com/NUS-MTech-Capstone/sts/internal/model"
)

func (s *Service) ValidateAccess(ctx context.Context, req model.ValidateRequest) model.ValidateResponse {
	if req.UserID == "" {
		return model.ValidateResponse{Allowed: false, Reason: "userId is required"}
	}
	if req.Action != "start" && req.Action != "rejoin" && req.Action != "observe" {
		return model.ValidateResponse{Allowed: false, Reason: "action must be start, rejoin or observe"}
	}
	if req.Action == "start" && (req.HostID == "" || req.CRID == "") {
		return model.ValidateResponse{Allowed: false, Reason: "hostId and crId are required for start"}
	}
	if req.Action == "start" && s.changeRequests != nil {
		if _, err := s.changeRequests.Get(ctx, req.CRID); err != nil {
			return model.ValidateResponse{Allowed: false, Reason: err.Error()}
		}
	}
	if req.Action == "start" && s.serverInventory != nil {
		if _, err := s.serverInventory.Get(ctx, req.HostID); err != nil {
			return model.ValidateResponse{Allowed: false, Reason: err.Error()}
		}
	}
	if (req.Action == "rejoin" || req.Action == "observe") && req.SessionID == "" {
		return model.ValidateResponse{Allowed: false, Reason: "sessionId is required"}
	}
	return model.ValidateResponse{Allowed: true}
}
