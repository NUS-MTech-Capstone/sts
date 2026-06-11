package service

import (
	"context"

	"github.com/NUS-MTech-Capstone/sts/internal/model"
)

func (s *Service) ValidateAccess(_ context.Context, req model.ValidateRequest) model.ValidateResponse {
	if req.UserID == "" {
		return model.ValidateResponse{Allowed: false, Reason: "userId is required"}
	}
	if req.Action == "start" && (req.HostID == "" || req.CRID == "") {
		return model.ValidateResponse{Allowed: false, Reason: "hostId and crId are required for start"}
	}
	if (req.Action == "rejoin" || req.Action == "observe") && req.SessionID == "" {
		return model.ValidateResponse{Allowed: false, Reason: "sessionId is required"}
	}
	return model.ValidateResponse{Allowed: true}
}
