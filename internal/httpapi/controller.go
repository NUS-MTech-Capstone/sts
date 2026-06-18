package httpapi

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/NUS-MTech-Capstone/sts/internal/model"
	"github.com/NUS-MTech-Capstone/sts/internal/observability"
)

func (s *Server) validate(w http.ResponseWriter, r *http.Request) {
	var req model.ValidateRequest
	if !decode(w, r, &req) {
		return
	}
	resp := s.svc.ValidateAccess(r.Context(), req)
	if !resp.Allowed {
		writeJSON(w, http.StatusForbidden, resp)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) issueToken(w http.ResponseWriter, r *http.Request) {
	var req model.SessionTokenRequest
	if !decode(w, r, &req) {
		return
	}
	resp, err := s.svc.IssueSessionToken(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	slog.InfoContext(r.Context(), "SessionTokenIssued",
		"requestId", observability.RequestID(r.Context()),
		"sessionId", req.SessionID,
		"userId", req.UserID,
		"hostId", req.HostID,
		"crId", req.CRID,
		"action", req.Action,
		"mode", req.Mode,
	)
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) validateToken(w http.ResponseWriter, r *http.Request) {
	var req model.TokenValidateRequest
	if !decode(w, r, &req) {
		return
	}
	resp := s.svc.ValidateSessionToken(r.Context(), req)
	if !resp.Allowed {
		writeJSON(w, http.StatusForbidden, resp)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) issueAutomationToken(w http.ResponseWriter, r *http.Request) {
	var req model.AutomationTokenRequest
	if !decode(w, r, &req) {
		return
	}
	token := bearerToken(r.Header.Get("Authorization"))
	resp, err := s.svc.IssueAutomationToken(r.Context(), token, req)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	slog.InfoContext(r.Context(), "AutomationTokenIssued",
		"requestId", observability.RequestID(r.Context()),
		"runId", req.RunID,
		"incidentId", req.IncidentID,
		"phase", req.Phase,
	)
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) validateAutomationToken(w http.ResponseWriter, r *http.Request) {
	var req model.AutomationTokenValidateRequest
	if !decode(w, r, &req) {
		return
	}
	resp := s.svc.ValidateAutomationToken(r.Context(), req)
	if !resp.Allowed {
		writeJSON(w, http.StatusForbidden, resp)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}
