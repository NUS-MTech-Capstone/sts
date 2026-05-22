package httpapi

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/NUS-MTech-Capstone/sts/internal/model"
	"github.com/NUS-MTech-Capstone/sts/internal/service"
)

type Server struct {
	svc *service.Service
	mux *http.ServeMux
}

func New(svc *service.Service) *Server {
	s := &Server{svc: svc, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL.Path)
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	s.mux.HandleFunc("POST /validate", s.validate)
	s.mux.HandleFunc("POST /tokens/session", s.issueToken)
	s.mux.HandleFunc("POST /tokens/validate", s.validateToken)
}

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

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"message": message}})
}
