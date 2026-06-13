package server_inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

type Static struct {
	servers map[string]Server
}

func NewStatic(rawJSON string) (*Static, error) {
	var servers map[string]Server
	if err := json.Unmarshal([]byte(rawJSON), &servers); err != nil {
		return nil, fmt.Errorf("decode SERVER_INVENTORY_STATIC_JSON: %w", err)
	}
	for hostID, server := range servers {
		if server.HostID == "" {
			server.HostID = hostID
		}
		if server.ConnectionType == "" {
			server.ConnectionType = "ssh"
		}
		servers[hostID] = server
	}
	return &Static{servers: servers}, nil
}

func (s *Static) Get(_ context.Context, hostID string) (Server, error) {
	server, ok := s.servers[hostID]
	if !ok {
		return Server{}, errors.New("server not found")
	}
	return server, nil
}
