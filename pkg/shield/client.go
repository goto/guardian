package shield

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// User represents a user record in Shield
type User struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Email     string                 `json:"email"`
	Metadata  map[string]interface{} `json:"metadata"`
	CreatedAt time.Time              `json:"createdAt"`
	UpdatedAt time.Time              `json:"updatedAt"`
}

type GetUserResponse struct {
	User User `json:"user"`
}

// Group represents a single team/group in Shield
type Group struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Slug     string                 `json:"slug"`
	OrgID    string                 `json:"orgId"`
	Metadata map[string]interface{} `json:"metadata"`
}

type GetUserGroupsResponse struct {
	Groups []Group `json:"groups"`
}

// Client defines the interface for interacting with the Shield API
type Client interface {
	GetUser(ctx context.Context, email string) (*User, error)
	GetUserGroups(ctx context.Context, userID string) ([]Group, error)
}

type client struct {
	httpClient *http.Client
	baseURL    string
	authEmail  string
}

// NewClient initializes a new Shield API client
func NewClient(baseURL, authEmail string) Client {
	return &client{
		httpClient: http.DefaultClient,
		baseURL:    baseURL,
		authEmail:  authEmail,
	}
}

// GetUser fetches a Shield user by their email address
func (c *client) GetUser(ctx context.Context, email string) (*User, error) {
	endpoint := fmt.Sprintf("%s/admin/v1beta1/users/%s", c.baseURL, email)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Auth-Email", c.authEmail)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request to shield: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shield API returned unexpected status %d for user %s", resp.StatusCode, email)
	}

	var result GetUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode shield response: %w", err)
	}

	return &result.User, nil
}

// GetUserGroups fetches all groups a specific user belongs to by their UUID
func (c *client) GetUserGroups(ctx context.Context, userID string) ([]Group, error) {
	endpoint := fmt.Sprintf("%s/admin/v1beta1/users/%s/groups", c.baseURL, userID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Auth-Email", c.authEmail)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request to shield: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shield API returned unexpected status %d for user groups %s", resp.StatusCode, userID)
	}

	var result GetUserGroupsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode shield response: %w", err)
	}

	return result.Groups, nil
}
