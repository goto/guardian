package shield

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/goto/guardian/domain"
)

type client struct {
	httpClient *http.Client
	baseURL    string
	authHeader string
	authEmail  string
}

// NewClient initializes a new Shield API client
func NewClient(baseURL, authHeader, authEmail string) domain.UserManagement {
	return &client{
		httpClient: http.DefaultClient,
		baseURL:    baseURL,
		authHeader: authHeader,
		authEmail:  authEmail,
	}
}

// GetUser fetches a Shield user by their email address
func (c *client) GetUser(ctx context.Context, email string) (*domain.User, error) {
	endpoint := fmt.Sprintf("%s/admin/v1beta1/users/%s", c.baseURL, email)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set(c.authHeader, c.authEmail)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request to shield: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shield API returned unexpected status %d for user %s", resp.StatusCode, email)
	}

	var result domain.GetUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode shield response: %w", err)
	}

	return &result.User, nil
}

// GetUserGroups fetches all groups a specific user belongs to by their UUID
func (c *client) GetUserGroups(ctx context.Context, userID string) ([]domain.Group, error) {
	endpoint := fmt.Sprintf("%s/admin/v1beta1/users/%s/groups", c.baseURL, userID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set(c.authHeader, c.authEmail)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request to shield: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shield API returned unexpected status %d for user groups %s", resp.StatusCode, userID)
	}

	var result domain.GetUserGroupsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode shield response: %w", err)
	}

	return result.Groups, nil
}
