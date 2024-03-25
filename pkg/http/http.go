package http

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/mcuadros/go-defaults"
	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
)

type HTTPAuthConfig struct {
	Type string `mapstructure:"type" json:"type" yaml:"type" validate:"required,oneof=basic api_key bearer google_idtoken"`

	// basic auth
	Username string `mapstructure:"username,omitempty" json:"username,omitempty" yaml:"username,omitempty" validate:"required_if=Type basic"`
	Password string `mapstructure:"password,omitempty" json:"password,omitempty" yaml:"password,omitempty" validate:"required_if=Type basic"`

	// api key
	In    string `mapstructure:"in,omitempty" json:"in,omitempty" yaml:"in,omitempty" validate:"required_if=Type api_key,omitempty,oneof=query header"`
	Key   string `mapstructure:"key,omitempty" json:"key,omitempty" yaml:"key,omitempty" validate:"required_if=Type api_key"`
	Value string `mapstructure:"value,omitempty" json:"value,omitempty" yaml:"value,omitempty" validate:"required_if=Type api_key"`

	// bearer
	Token string `mapstructure:"token,omitempty" json:"token,omitempty" yaml:"token,omitempty" validate:"required_if=Type bearer"`

	// google_idtoken
	Audience string `mapstructure:"audience,omitempty" json:"audience,omitempty" yaml:"audience,omitempty" validate:"required_if=Type google_idtoken"`
	// CredentialsJSONBase64 accept a base64 encoded JSON stringified credentials
	CredentialsJSONBase64 string `mapstructure:"credentials_json_base64,omitempty" json:"credentials_json_base64,omitempty" yaml:"credentials_json_base64,omitempty"`
}

// HTTPClientConfig is the configuration required by iam.Client
type HTTPClientConfig struct {
	URL     string            `mapstructure:"url" json:"url" yaml:"url" validate:"required,url"`
	Headers map[string]string `mapstructure:"headers,omitempty" json:"headers,omitempty" yaml:"headers,omitempty"`
	Auth    *HTTPAuthConfig   `mapstructure:"auth,omitempty" json:"auth,omitempty" yaml:"auth,omitempty" validate:"omitempty,dive"`

	HTTPClient *http.Client `mapstructure:"-" json:"-" yaml:"-"`
	Validator  *validator.Validate
}

// HTTPClient wraps the http client for external approver resolver service
type HTTPClient struct {
	httpClient *http.Client
	config     *HTTPClientConfig

	url string
}

// NewHTTPClient returns *iam.Client
func NewHTTPClient(config *HTTPClientConfig) (*HTTPClient, error) {
	defaults.SetDefaults(config)
	if err := validator.New().Struct(config); err != nil {
		return nil, err
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	if config.Auth.Type == "google_idtoken" {
		var creds []byte
		switch {
		case config.Auth.CredentialsJSONBase64 != "":
			v, err := base64.StdEncoding.DecodeString(config.Auth.CredentialsJSONBase64)
			if err != nil {
				return nil, fmt.Errorf("decoding credentials_json_base64: %w", err)
			}
			creds = v
		default:
			return nil, fmt.Errorf("missing credentials for google_idtoken auth")
		}

		ctx := context.Background()
		ts, err := idtoken.NewTokenSource(ctx, config.Auth.Audience, idtoken.WithCredentialsJSON(creds))
		if err != nil {
			return nil, err
		}
		httpClient = oauth2.NewClient(ctx, ts)
	}

	return &HTTPClient{
		httpClient: httpClient,
		config:     config,
		url:        config.URL,
	}, nil
}

func (c *HTTPClient) setAuth(req *http.Request) {
	if c.config.Auth != nil {
		switch c.config.Auth.Type {
		case "basic":
			req.SetBasicAuth(c.config.Auth.Username, c.config.Auth.Password)
		case "api_key":
			switch c.config.Auth.In {
			case "query":
				q := req.URL.Query()
				q.Add(c.config.Auth.Key, c.config.Auth.Value)
				req.URL.RawQuery = q.Encode()
			case "header":
				req.Header.Add(c.config.Auth.Key, c.config.Auth.Value)
			default:
			}
		case "bearer":
			req.Header.Add("Authorization", "Bearer "+c.config.Auth.Token)
		default:
		}
	}
}

func (c *HTTPClient) MakeRequest(ctx context.Context) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, c.config.URL, nil)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Accept", "application/json")

	for k, v := range c.config.Headers {
		req.Header.Set(k, v)
	}
	c.setAuth(req)

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	return res, nil
}
