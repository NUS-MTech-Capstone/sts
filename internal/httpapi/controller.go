package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/NUS-MTech-Capstone/sts/internal/events"
	"github.com/NUS-MTech-Capstone/sts/internal/model"
	"github.com/NUS-MTech-Capstone/sts/internal/observability"
	"github.com/NUS-MTech-Capstone/sts/internal/service"
)

func (s *Server) validate(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req model.ValidateRequest
	if !decode(w, r, &req) {
		return
	}
	resp := s.svc.ValidateAccess(r.Context(), req)
	if !resp.Allowed {
		observability.EmitCount("sts", "AuthFailures", map[string]string{"Component": "access", "Reason": "denied"})
		slog.WarnContext(r.Context(), "AccessDenied",
			"requestId", observability.RequestID(r.Context()),
			"userId", req.UserID,
			"hostId", req.HostID,
			"crId", req.CRID,
			"sessionId", req.SessionID,
			"action", req.Action,
			"status", "denied",
			"durationMs", time.Since(start).Milliseconds(),
			"reason", resp.Reason,
		)
		s.events.Emit(r.Context(), events.Event{
			EventType:  "AccessDenied",
			RequestID:  observability.RequestID(r.Context()),
			UserID:     req.UserID,
			HostID:     req.HostID,
			CRID:       req.CRID,
			SessionID:  req.SessionID,
			Action:     req.Action,
			Outcome:    "denied",
			ReasonCode: "denied",
		})
		writeJSON(w, http.StatusForbidden, resp)
		return
	}
	slog.InfoContext(r.Context(), "AccessAllowed",
		"requestId", observability.RequestID(r.Context()),
		"userId", req.UserID,
		"hostId", req.HostID,
		"crId", req.CRID,
		"sessionId", req.SessionID,
		"action", req.Action,
		"status", "allowed",
		"durationMs", time.Since(start).Milliseconds(),
	)
	s.events.Emit(r.Context(), events.Event{
		EventType: "AccessAllowed",
		RequestID: observability.RequestID(r.Context()),
		UserID:    req.UserID,
		HostID:    req.HostID,
		CRID:      req.CRID,
		SessionID: req.SessionID,
		Action:    req.Action,
		Outcome:   "allowed",
	})
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) issueToken(w http.ResponseWriter, r *http.Request) {
	var req model.SessionTokenRequest
	if !decode(w, r, &req) {
		return
	}
	resp, err := s.svc.IssueSessionToken(r.Context(), req)
	if err != nil {
		observability.EmitCount("sts", "STSErrors", map[string]string{"Component": "token", "Reason": "issue_failed"})
		if errors.Is(err, service.ErrAccessDenied) {
			writeError(w, http.StatusForbidden, err.Error())
		} else {
			writeError(w, http.StatusBadRequest, "session token issuance failed")
		}
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
		observability.EmitCount("sts", "AuthFailures", map[string]string{"Component": "token", "Reason": "denied"})
		slog.WarnContext(r.Context(), "AccessDenied",
			"requestId", observability.RequestID(r.Context()),
			"sessionId", req.SessionID,
			"userId", req.UserID,
			"hostId", req.HostID,
			"crId", req.CRID,
			"action", req.Action,
			"mode", req.Mode,
			"status", "denied",
			"reason", resp.Reason,
		)
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

func (s *Server) validateWorkloadIdentity(w http.ResponseWriter, r *http.Request) {
	subject, err := s.svc.ValidateWorkloadIdentity(r.Context(), bearerToken(r.Header.Get("Authorization")))
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	const prefix = "system:serviceaccount:"
	parts := strings.Split(strings.TrimPrefix(subject, prefix), ":")
	if !strings.HasPrefix(subject, prefix) || len(parts) != 2 {
		writeError(w, http.StatusForbidden, "workload identity is not authorized")
		return
	}
	writeJSON(w, http.StatusOK, model.WorkloadIdentityResponse{
		Subject: subject, Namespace: parts[0], ServiceAccount: parts[1],
	})
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}
