package service

import (
	"context"
	"sync"
	"time"

	"github.com/NUS-MTech-Capstone/sts/internal/change_request"
	"github.com/NUS-MTech-Capstone/sts/internal/server_inventory"
)

type tokenRecord struct {
	sessionID string
	userID    string
	mode      string
	expiresAt time.Time
}

type ChangeRequestClient interface {
	Get(context.Context, string) (change_request.ChangeRequest, error)
}

type ServerInventoryClient interface {
	Get(context.Context, string) (server_inventory.Server, error)
}

type Service struct {
	mu              sync.RWMutex
	tokens          map[string]tokenRecord
	ttl             time.Duration
	now             func() time.Time
	changeRequests  ChangeRequestClient
	serverInventory ServerInventoryClient
}

func New(
	ttl time.Duration,
	changeRequests ChangeRequestClient,
	serverInventory ServerInventoryClient,
) *Service {
	return &Service{
		tokens:          make(map[string]tokenRecord),
		ttl:             ttl,
		now:             time.Now,
		changeRequests:  changeRequests,
		serverInventory: serverInventory,
	}
}
