package alertmanager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	sirenHTTPTimeout = 30 * time.Second

	guardianSirenDriftCheckTemplate = "guardian-grant-drift-check"

	notificationsEndpoint = "/v1beta1/notifications"
)

var (
	alertToTemplateMap = map[string]string{
		GrantDriftCheckEvent: guardianSirenDriftCheckTemplate,
	}
)

type sirenPayload struct {
	Data     map[string]interface{} `json:"data"`
	Template string                 `json:"template"`
	Labels   map[string]string      `json:"labels"`
}

type SirenClient struct {
	host        string
	environment string
	httpClient  *http.Client
}

func NewSirenClient(host string, environment string) *SirenClient {
	return &SirenClient{
		host:        host,
		environment: environment,
		httpClient: &http.Client{
			Timeout: sirenHTTPTimeout,
		},
	}
}

func (c *SirenClient) Send(ctx context.Context, event Event) error {
	sirenTmpl := alertToTemplateMap[event.Title]
	if sirenTmpl == "" {
		return fmt.Errorf("no siren template mapped for event title: %s", event.Title)
	}

	payload := sirenPayload{
		Data:     event.Data,
		Template: sirenTmpl,
		Labels: map[string]string{
			"severity":    event.Severity,
			"environment": c.environment,
			"team":        event.Team,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling siren payload: %w", err)
	}

	endpoint := fmt.Sprintf("%s%s", c.host, notificationsEndpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating siren request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending siren event: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("siren returned non-200 status: %s, body: %s", res.Status, string(body))
	}
	return nil
}
