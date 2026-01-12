package custom_http

import (
	"fmt"

	"github.com/goto/guardian/domain"
	"github.com/mitchellh/mapstructure"
)

type Config struct {
	ProviderConfig *domain.ProviderConfig
}

type Credentials struct {
	BaseURL string            `mapstructure:"base_url" yaml:"base_url" validate:"required,url"`
	Headers map[string]string `mapstructure:"headers" yaml:"headers"`
}

type ResourceMapping struct {
	Name string `mapstructure:"name" yaml:"name" validate:"required"`
	ID   string `mapstructure:"id" yaml:"id" validate:"required"`
	URN  string `mapstructure:"urn" yaml:"urn" validate:"required"`
}

type APIEndpoint struct {
	Path   string                 `mapstructure:"path" yaml:"path" validate:"required"`
	Method string                 `mapstructure:"method" yaml:"method" validate:"required,oneof=GET POST PUT DELETE PATCH"`
	Body   map[string]interface{} `mapstructure:"body" yaml:"body"`
}

type APIConfiguration struct {
	Resources APIEndpoint `mapstructure:"resources" yaml:"resources" validate:"required"`
	Grant     APIEndpoint `mapstructure:"grant" yaml:"grant" validate:"required"`
	Revoke    APIEndpoint `mapstructure:"revoke" yaml:"revoke" validate:"required"`
	Members   APIEndpoint `mapstructure:"members" yaml:"members"` // Optional: for fetching group members/approvers
}

type ProviderConfiguration struct {
	Mapping ResourceMapping  `mapstructure:"mapping" yaml:"mapping" validate:"required"`
	API     APIConfiguration `mapstructure:"api" yaml:"api" validate:"required"`
}

func NewConfig(pc *domain.ProviderConfig) *Config {
	return &Config{
		ProviderConfig: pc,
	}
}

func (c *Config) ParseAndValidate() error {
	return c.validateProviderConfig()
}

func (c *Config) validateProviderConfig() error {
	if c.ProviderConfig.Type != "custom_http" {
		return fmt.Errorf("invalid provider type: %q, expected: %q", c.ProviderConfig.Type, "custom_http")
	}

	// Validate credentials
	var creds Credentials
	if err := mapstructure.Decode(c.ProviderConfig.Credentials, &creds); err != nil {
		return fmt.Errorf("invalid credentials format: %w", err)
	}

	if creds.BaseURL == "" {
		return fmt.Errorf("base_url is required in credentials")
	}

	// Validate provider configuration exists in labels
	if c.ProviderConfig.Labels == nil {
		return fmt.Errorf("provider configuration is required in labels")
	}

	configData, exists := c.ProviderConfig.Labels["config"]
	if !exists {
		return fmt.Errorf("provider configuration is required in labels.config")
	}

	// Parse configuration from labels.config (should be JSON string)
	var config ProviderConfiguration
	if err := mapstructure.Decode(configData, &config); err != nil {
		return fmt.Errorf("invalid provider configuration: %w", err)
	}

	// Validate mapping fields
	if config.Mapping.Name == "" || config.Mapping.ID == "" || config.Mapping.URN == "" {
		return fmt.Errorf("mapping fields (name, id, urn) are all required")
	}

	// Validate API endpoints
	if config.API.Resources.Path == "" || config.API.Resources.Method == "" {
		return fmt.Errorf("resources API endpoint (path, method) is required")
	}

	if config.API.Grant.Path == "" || config.API.Grant.Method == "" {
		return fmt.Errorf("grant API endpoint (path, method) is required")
	}

	if config.API.Revoke.Path == "" || config.API.Revoke.Method == "" {
		return fmt.Errorf("revoke API endpoint (path, method) is required")
	}

	// Validate that we have at least one resource configured
	if len(c.ProviderConfig.Resources) == 0 {
		return fmt.Errorf("at least one resource configuration is required")
	}

	return nil
}
