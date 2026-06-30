package identities

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-playground/validator/v10"
	"github.com/goto/guardian/domain"
)

type ShieldClientConfig struct {
	Host       string `mapstructure:"host" json:"host" yaml:"host" validate:"required,url"`
	AuthHeader string `mapstructure:"auth_header" json:"auth_header" yaml:"auth_header" validate:"required"`
	AuthEmail  string `mapstructure:"auth_email" json:"auth_email" yaml:"auth_email" validate:"required,email"`

	validator *validator.Validate
	crypto    domain.Crypto
}

func (c *ShieldClientConfig) Validate() error {
	return c.validator.Struct(c)
}

func (c *ShieldClientConfig) Encrypt() error {
	return nil
}

func (c *ShieldClientConfig) Decrypt() error {
	return nil
}

type shieldGetUserResponse struct {
	User domain.User `json:"user"`
}

type shieldGetUserGroupsResponse struct {
	Groups []domain.Group `json:"groups"`
}

type shieldClient struct {
	baseURL    *url.URL
	authHeader string
	authEmail  string

	httpClient *http.Client
}

func NewShieldClient(config *ShieldClientConfig) (*shieldClient, error) {
	if err := validator.New().Struct(config); err != nil {
		return nil, err
	}

	baseURL, err := url.Parse(config.Host)
	if err != nil {
		return nil, err
	}

	return &shieldClient{
		baseURL:    baseURL,
		authHeader: config.AuthHeader,
		authEmail:  config.AuthEmail,
		httpClient: http.DefaultClient,
	}, nil
}

func (c *shieldClient) GetUser(userEmailOrId string) (interface{}, error) {
	req, err := c.newRequest(http.MethodGet, fmt.Sprintf("/admin/v1beta1/users/%s", userEmailOrId))
	if err != nil {
		return nil, err
	}

	var response shieldGetUserResponse
	if err := c.do(req, &response); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"user": response.User,
	}, nil
}

func (c *shieldClient) GetUserGroups(userID string) (interface{}, error) {
	req, err := c.newRequest(http.MethodGet, fmt.Sprintf("/admin/v1beta1/users/%s/groups", userID))
	if err != nil {
		return nil, err
	}

	var response shieldGetUserGroupsResponse
	if err := c.do(req, &response); err != nil {
		return nil, err
	}

	return response.Groups, nil
}

func (c *shieldClient) newRequest(method, path string) (*http.Request, error) {
	u, err := c.baseURL.Parse(path)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set(c.authHeader, c.authEmail)
	return req, nil
}

func (c *shieldClient) do(req *http.Request, v interface{}) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("shield API returned unexpected status %d for %s", resp.StatusCode, req.URL.Path)
	}

	return json.NewDecoder(resp.Body).Decode(v)
}
