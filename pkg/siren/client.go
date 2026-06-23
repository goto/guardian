package siren

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// NotificationRequest defines the payload sent to Siren.
// Siren uses the Labels to determine which receivers (Slack, PagerDuty, Lark) should get the alert.
type NotificationRequest struct {
	Labels   map[string]string      `json:"labels"`
	Template string                 `json:"template"`
	Data     map[string]interface{} `json:"data"` // Variables injected into the template
}

// Client defines the interface for interacting with the Siren API
type Client interface {
	PostNotification(ctx context.Context, req NotificationRequest) error
}

type client struct {
	httpClient *http.Client
	baseURL    string
}

// NewClient initializes a new Siren API client
func NewClient(baseURL string) Client {
	return &client{
		httpClient: http.DefaultClient,
		baseURL:    baseURL,
	}
}

func (c *client) PostNotification(ctx context.Context, req NotificationRequest) error {
	endpoint := fmt.Sprintf("%s/v1beta1/notifications", c.baseURL)

	payloadBytes, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal siren notification request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to execute request to siren: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("siren API returned unexpected status %d", resp.StatusCode)
	}

	return nil
}
