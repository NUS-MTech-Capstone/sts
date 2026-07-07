package httpapi

import (
	"net/http"

	"github.com/NUS-MTech-Capstone/sts/internal/events"
	"github.com/NUS-MTech-Capstone/sts/internal/observability"
	"github.com/NUS-MTech-Capstone/sts/internal/service"
)

type Server struct {
	svc    *service.Service
	mux    *http.ServeMux
	events events.Publisher
}

func New(svc *service.Service, publishers ...events.Publisher) *Server {
	publisher := events.Publisher(events.NoopPublisher{})
	if len(publishers) > 0 && publishers[0] != nil {
		publisher = publishers[0]
	}
	s := &Server{svc: svc, mux: http.NewServeMux(), events: publisher}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	observability.RequestIDMiddleware(observability.LogRequests(apiVersionMiddleware(s.mux))).ServeHTTP(w, r)
}
