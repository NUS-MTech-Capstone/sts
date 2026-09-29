package httpapi

import (
	"net/http"

	"github.com/NUS-MTech-Capstone/sts/api"
)

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	s.mux.HandleFunc("GET /openapi.yaml", serveYAML(api.OpenAPI))
	s.mux.HandleFunc("POST /validate", s.validate)
	s.mux.HandleFunc("POST /tokens/session", s.issueToken)
	s.mux.HandleFunc("POST /tokens/validate", s.validateToken)
	s.mux.HandleFunc("POST /tokens/automation", s.issueAutomationToken)
	s.mux.HandleFunc("POST /tokens/automation/validate", s.validateAutomationToken)
	s.mux.HandleFunc("POST /workloads/validate", s.validateWorkloadIdentity)
}
