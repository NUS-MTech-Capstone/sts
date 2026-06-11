package httpapi

import (
	"log"
	"net/http"

	"github.com/NUS-MTech-Capstone/sts/internal/model"
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
	log.Printf("SessionTokenIssued sessionId=%s userId=%s mode=%s", req.SessionID, req.UserID, req.Mode)
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
