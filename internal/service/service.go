package service

import (
	"context"
	"sync"
	"time"

	"github.com/NUS-MTech-Capstone/sts/internal/model"
)

type tokenRecord struct {
	sessionID string
	expiresAt time.Time
}

type Service struct {
	mu     sync.RWMutex
	tokens map[string]tokenRecord
	ttl    time.Duration
	now    func() time.Time
}

func New(ttl time.Duration) *Service {
	return &Service{tokens: make(map[string]tokenRecord), ttl: ttl, now: time.Now}
}
