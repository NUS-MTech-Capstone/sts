package service

import (
	"context"
	"time"

	"github.com/NUS-MTech-Capstone/sts/internal/change_request"
	"github.com/NUS-MTech-Capstone/sts/internal/server_inventory"
)

type TokenConfig struct {
	TTL        time.Duration
	SigningKey []byte
	Issuer     string
	Audience   string
	ClockSkew  time.Duration
}

type ChangeRequestClient interface {
	Get(context.Context, string) (change_request.ChangeRequest, error)
}

type ServerInventoryClient interface {
	Get(context.Context, string) (server_inventory.Server, error)
}

type Service struct {
	tokenConfig     TokenConfig
	now             func() time.Time
	changeRequests  ChangeRequestClient
	serverInventory ServerInventoryClient
}

func New(
	tokenConfig TokenConfig,
	changeRequests ChangeRequestClient,
	serverInventory ServerInventoryClient,
) *Service {
	tokenConfig.SigningKey = append([]byte(nil), tokenConfig.SigningKey...)
	return &Service{
		tokenConfig:     tokenConfig,
		now:             time.Now,
		changeRequests:  changeRequests,
		serverInventory: serverInventory,
	}
}
