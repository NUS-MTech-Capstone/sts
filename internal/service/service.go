package service

import (
	"context"
	"errors"
	"time"

	"github.com/NUS-MTech-Capstone/sts/internal/change_request"
	"github.com/NUS-MTech-Capstone/sts/internal/server_inventory"
)

type TokenConfig struct {
	TTL           time.Duration
	AutomationTTL time.Duration
	SigningKey    []byte
	Issuer        string
	Audience      string
	ClockSkew     time.Duration
}

type ChangeRequestClient interface {
	Get(context.Context, string) (change_request.ChangeRequest, error)
}

type ServerInventoryClient interface {
	Get(context.Context, string) (server_inventory.Server, error)
}

type WorkloadValidator interface {
	Validate(context.Context, string) (string, error)
}

type Service struct {
	tokenConfig     TokenConfig
	now             func() time.Time
	changeRequests  ChangeRequestClient
	serverInventory ServerInventoryClient
	workloads       WorkloadValidator
	identities      WorkloadValidator
}

func New(
	tokenConfig TokenConfig,
	changeRequests ChangeRequestClient,
	serverInventory ServerInventoryClient,
	workloads ...WorkloadValidator,
) *Service {
	tokenConfig.SigningKey = append([]byte(nil), tokenConfig.SigningKey...)
	svc := &Service{
		tokenConfig:     tokenConfig,
		now:             time.Now,
		changeRequests:  changeRequests,
		serverInventory: serverInventory,
	}
	if len(workloads) > 0 {
		svc.workloads = workloads[0]
	}
	if len(workloads) > 1 {
		svc.identities = workloads[1]
	}
	return svc
}

func (s *Service) ValidateWorkloadIdentity(ctx context.Context, token string) (string, error) {
	if s.identities == nil {
		return "", errors.New("workload identity validation is not configured")
	}
	subject, err := s.identities.Validate(ctx, token)
	if err != nil {
		return "", errors.New("workload identity is not authorized")
	}
	return subject, nil
}
