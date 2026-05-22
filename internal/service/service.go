package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/NUS-MTech-Capstone/sts/internal/model"
)

type tokenRecord struct {
	sessionID string
	expiresAt time.Time
}

type Service struct {
	mu     sync.RWMutex
	tokens map[string]tokenRecord
	ttl    time.Duration
	now    func() time.Time
}

func New(ttl time.Duration) *Service {
	return &Service{tokens: make(map[string]tokenRecord), ttl: ttl, now: time.Now}
}

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

func (s *Service) IssueSessionToken(_ context.Context, req model.SessionTokenRequest) (model.SessionTokenResponse, error) {
	if req.SessionID == "" || req.UserID == "" {
		return model.SessionTokenResponse{}, errors.New("sessionId and userId are required")
	}
	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		return model.SessionTokenResponse{}, err
	}
	token := "ddm_" + hex.EncodeToString(tokenBytes)
	expiresAt := s.now().UTC().Add(s.ttl)
	s.mu.Lock()
	s.tokens[token] = tokenRecord{sessionID: req.SessionID, expiresAt: expiresAt}
	s.mu.Unlock()
	return model.SessionTokenResponse{SessionToken: token, ExpiresAt: expiresAt}, nil
}

func (s *Service) ValidateSessionToken(_ context.Context, req model.TokenValidateRequest) model.ValidateResponse {
	s.mu.RLock()
	record, ok := s.tokens[req.Token]
	s.mu.RUnlock()
	if !ok || req.Token == "" {
		return model.ValidateResponse{Allowed: false, Reason: "token not found"}
	}
	if record.sessionID != req.SessionID {
		return model.ValidateResponse{Allowed: false, Reason: "token session mismatch"}
	}
	if !record.expiresAt.After(s.now()) {
		return model.ValidateResponse{Allowed: false, Reason: "token expired"}
	}
	return model.ValidateResponse{Allowed: true}
}
