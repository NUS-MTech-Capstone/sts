package server_inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	client  *http.Client
}

type Server struct {
	HostID             string `json:"hostId"`
	Hostname           string `json:"hostname,omitempty"`
	Address            string `json:"address,omitempty"`
	Status             string `json:"status,omitempty"`
	ConnectionType     string `json:"connectionType,omitempty"`
	Username           string `json:"username,omitempty"`
	CredentialSecretID string `json:"credentialSecretId,omitempty"`
	HostPublicKey      string `json:"hostPublicKey,omitempty"`
}

func New(baseURL string, timeout time.Duration) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

// Get retrieves a server. The endpoint contract is a placeholder until the
// server-inventory service is added to this workspace.
func (c *Client) Get(ctx context.Context, hostID string) (Server, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		c.baseURL+"/servers/"+url.PathEscape(hostID),
		nil,
	)
	if err != nil {
		return Server{}, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return Server{}, fmt.Errorf("get server: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Server{}, fmt.Errorf("server-inventory service returned status %d", resp.StatusCode)
	}

	var server Server
	if err := json.NewDecoder(resp.Body).Decode(&server); err != nil {
		return Server{}, fmt.Errorf("decode server: %w", err)
	}
	return server, nil
}
