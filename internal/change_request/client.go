package change_request

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/NUS-MTech-Capstone/sts/internal/observability"
)

type Client struct {
	baseURL string
	client  *http.Client
}

type ChangeRequest struct {
	CRID                  string    `json:"crId"`
	UserID                string    `json:"userId,omitempty"`
	HostIDs               []string  `json:"hostIds,omitempty"`
	Status                string    `json:"status,omitempty"`
	ImplementationStartAt time.Time `json:"implementationStartAt"`
	ImplementationEndAt   time.Time `json:"implementationEndAt"`
	AllowedRoles          []string  `json:"allowedRoles"`
}

func New(baseURL string, timeout time.Duration) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

// Get retrieves trusted CR metadata from the configured backend.
func (c *Client) Get(ctx context.Context, crID string) (ChangeRequest, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		c.baseURL+"/change-requests/"+url.PathEscape(crID),
		nil,
	)
	if err != nil {
		return ChangeRequest{}, err
	}
	observability.SetRequestHeaders(ctx, req)

	resp, err := c.client.Do(req)
	if err != nil {
		return ChangeRequest{}, fmt.Errorf("get change request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ChangeRequest{}, fmt.Errorf("change-request service returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return ChangeRequest{}, fmt.Errorf("invalid change-request response size or read failure")
	}
	var changeRequest ChangeRequest
	if err := json.Unmarshal(body, &changeRequest); err != nil {
		return ChangeRequest{}, fmt.Errorf("decode change request: %w", err)
	}
	return changeRequest, nil
}
