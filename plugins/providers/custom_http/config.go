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
	BaseURL        string                               `mapstructure:"base_url" yaml:"base_url" json:"base_url" validate:"required,url"`
	Headers        map[string]string                    `mapstructure:"headers" yaml:"headers" json:"headers"`
	ResourceRoutes map[string]ResourceTypeConfiguration `mapstructure:"resource_routes" yaml:"resource_routes" json:"resource_routes"`
}

// GetHeaders returns the headers map for HTTP requests
func (c *Credentials) GetHeaders() map[string]string {
	if c.Headers == nil {
		return make(map[string]string)
	}
	return c.Headers
}

type ResourceMapping struct {
	ID      string   `mapstructure:"id" yaml:"id" json:"id" validate:"required"`
	Name    string   `mapstructure:"name" yaml:"name" json:"name" validate:"required"`
	Type    string   `mapstructure:"type" yaml:"type" json:"type"` // Optional: type is inferred from configuration
	Details []string `mapstructure:"details" yaml:"details" json:"details"`
}

type APIEndpoint struct {
	Path   string                 `mapstructure:"path" yaml:"path" json:"path" validate:"required"`
	Method string                 `mapstructure:"method" yaml:"method" json:"method" validate:"required,oneof=GET POST PUT DELETE PATCH"`
	Body   map[string]interface{} `mapstructure:"body" yaml:"body" json:"body"`
}

type APIConfiguration struct {
	Resources APIEndpoint `mapstructure:"resources" yaml:"resources" json:"resources" validate:"required"`
	Grant     APIEndpoint `mapstructure:"grant" yaml:"grant" json:"grant" validate:"required"`
	Revoke    APIEndpoint `mapstructure:"revoke" yaml:"revoke" json:"revoke" validate:"required"`
}

type ResourceTypeConfiguration struct {
	API               APIConfiguration  `mapstructure:"api" yaml:"api" json:"api" validate:"required"`
	ResourceMapping   ResourceMapping   `mapstructure:"resource_mapping" yaml:"resource_mapping" json:"resource_mapping" validate:"required"`
	TemplateVariables map[string]string `mapstructure:"template_variables" yaml:"template_variables" json:"template_variables,omitempty"` // Custom template variables
}

type ProviderConfiguration struct {
	// Map of resource type -> its configuration
	ResourceTypes map[string]ResourceTypeConfiguration
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

	if len(creds.ResourceRoutes) == 0 {
		return fmt.Errorf("no resource routes found in credentials.resource_routes")
	}

	// Validate that we have configurations for all resource types
	for _, resource := range c.ProviderConfig.Resources {
		resourceConfig, exists := creds.ResourceRoutes[resource.Type]
		if !exists {
			return fmt.Errorf("missing configuration for resource type: %s", resource.Type)
		}

		// Validate required mapping fields
		if resourceConfig.ResourceMapping.ID == "" || resourceConfig.ResourceMapping.Name == "" {
			return fmt.Errorf("mapping fields (id, name) are required for resource type: %s", resource.Type)
		}

		// Validate API endpoints
		if resourceConfig.API.Resources.Path == "" || resourceConfig.API.Resources.Method == "" {
			return fmt.Errorf("resources API endpoint (path, method) is required for resource type: %s", resource.Type)
		}

		if resourceConfig.API.Grant.Path == "" || resourceConfig.API.Grant.Method == "" {
			return fmt.Errorf("grant API endpoint (path, method) is required for resource type: %s", resource.Type)
		}

		if resourceConfig.API.Revoke.Path == "" || resourceConfig.API.Revoke.Method == "" {
			return fmt.Errorf("revoke API endpoint (path, method) is required for resource type: %s", resource.Type)
		}
	}

	return nil
}
