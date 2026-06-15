package httpapi

import "net/http"

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	s.mux.HandleFunc("POST /validate", s.validate)
	s.mux.HandleFunc("POST /tokens/session", s.issueToken)
	s.mux.HandleFunc("POST /tokens/validate", s.validateToken)
	s.mux.HandleFunc("POST /tokens/automation", s.issueAutomationToken)
	s.mux.HandleFunc("POST /tokens/automation/validate", s.validateAutomationToken)
}
