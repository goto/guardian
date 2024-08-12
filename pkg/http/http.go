package http

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	validator "github.com/go-playground/validator/v10"
	defaults "github.com/mcuadros/go-defaults"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
	"net/http"
)

type HTTPAuthConfig struct {
	Type string `mapstructure:"type" json:"type" yaml:"type" validate:"required,oneof=basic api_key bearer google_idtoken google_oauth2"`

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
	URL        string            `mapstructure:"url" json:"url" yaml:"url" validate:"required,url"`
	Headers    map[string]string `mapstructure:"headers,omitempty" json:"headers,omitempty" yaml:"headers,omitempty"`
	Auth       *HTTPAuthConfig   `mapstructure:"auth,omitempty" json:"auth,omitempty" yaml:"auth,omitempty" validate:"omitempty,dive"`
	Method     string            `mapstructure:"method,omitempty" json:"method,omitempty" yaml:"method,omitempty"`
	Body       string            `mapstructure:"body,omitempty" json:"body,omitempty" yaml:"body,omitempty"`
	HTTPClient *http.Client      `mapstructure:"-" json:"-" yaml:"-"`
	Validator  *validator.Validate
}

// HTTPClient wraps the http client for external approver resolver service
type HTTPClient struct {
	httpClient *http.Client
	config     *HTTPClientConfig
	url        string
}
type HttpClientCreatorStruct struct {
}

type HttpClientCreator interface {
	GetHttpClientForGoogleOAuth2(ctx context.Context, creds []byte) (*http.Client, error)
	GetHttpClientForGoogleIdToken(ctx context.Context, creds []byte, audience string) (*http.Client, error)
}

// NewHTTPClient returns *iam.Client
func NewHTTPClient(config *HTTPClientConfig, clientCreator HttpClientCreator) (*HTTPClient, error) {
	defaults.SetDefaults(config)
	if err := validator.New().Struct(config); err != nil {
		return nil, err
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	if config.Auth != nil && (config.Auth.Type == "google_idtoken" || config.Auth.Type == "google_oauth2") {
		var creds []byte
		switch {
		case config.Auth.CredentialsJSONBase64 != "":
			var err error
			creds, err = decodeCredentials(config.Auth.CredentialsJSONBase64)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("missing credentials for google_idtoken or  google_oauth2 auth")
		}

		ctx := context.Background()
		var err error
		if config.Auth.Type == "google_idtoken" {
			httpClient, err = clientCreator.GetHttpClientForGoogleIdToken(ctx, creds, config.Auth.Audience)
			if err != nil {
				return nil, err
			}
		} else if config.Auth.Type == "google_oauth2" {
			httpClient, err = clientCreator.GetHttpClientForGoogleOAuth2(ctx, creds)
			if err != nil {
				return nil, err
			}
		}
	}

	return &HTTPClient{
		httpClient: httpClient,
		config:     config,
		url:        config.URL,
	}, nil
}

func (c *HTTPClient) GetClient() string {
	return c.url
}

func (c *HttpClientCreatorStruct) GetHttpClientForGoogleOAuth2(ctx context.Context, creds []byte) (*http.Client, error) {
	credsConfig, err := google.CredentialsFromJSON(ctx, creds, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, err
	}
	return oauth2.NewClient(ctx, credsConfig.TokenSource), nil
}

func (c *HttpClientCreatorStruct) GetHttpClientForGoogleIdToken(ctx context.Context, creds []byte, audience string) (*http.Client, error) {
	ts, err := idtoken.NewTokenSource(ctx, audience, idtoken.WithCredentialsJSON(creds))
	if err != nil {
		return nil, err
	}
	return oauth2.NewClient(ctx, ts), nil
}

func decodeCredentials(encodedCreds string) ([]byte, error) {
	v, err := base64.StdEncoding.DecodeString(encodedCreds)
	if err != nil {
		return nil, fmt.Errorf("decoding credentials_json_base64: %w", err)
	}
	return v, nil
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
	method := "GET"
	if c.config.Method != "" {
		method = c.config.Method
	}
	var body []byte
	if c.config.Method == "POST" {
		if c.config.Body != "" {
			body = []byte(c.config.Body)
		}
	}

	req, err := http.NewRequest(method, c.config.URL, bytes.NewBuffer(body))
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
