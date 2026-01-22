package custom_http

import (
	"encoding/base64"
	"fmt"

	"github.com/goto/guardian/domain"
	"github.com/mitchellh/mapstructure"
)

type Config struct {
	ProviderConfig *domain.ProviderConfig
}

// HeaderConfig allows configuration of headers with optional base64 decoding for secrets.
// Secrets are stored base64-encoded in the database and decoded when used by the client.
// Example YAML:
//
//	headers:
//	  Content-Type: "application/json"                    # Simple string
//	  Authorization:                                      # Secret (stored as base64 in DB)
//	    value: "bXktc2VjcmV0LXRva2Vu"                    # base64-encoded value
//	    is_secret: true
type HeaderConfig struct {
	Value    string `mapstructure:"value" yaml:"value" json:"value"`
	IsSecret bool   `mapstructure:"is_secret" yaml:"is_secret" json:"is_secret"`
}

type Credentials struct {
	BaseURL        string                               `mapstructure:"base_url" yaml:"base_url" json:"base_url" validate:"required,url"`
	Headers        map[string]interface{}               `mapstructure:"headers" yaml:"headers" json:"headers"`
	ResourceRoutes map[string]ResourceTypeConfiguration `mapstructure:"resource_routes" yaml:"resource_routes" json:"resource_routes"`
}

// GetHeaders returns the headers map for HTTP requests, base64 decoding secret values
func (c *Credentials) GetHeaders() map[string]string {
	if c.Headers == nil {
		return make(map[string]string)
	}

	result := make(map[string]string)
	for key, val := range c.Headers {
		switch v := val.(type) {
		case string:
			// Simple string value
			result[key] = v
		case map[string]interface{}:
			// HeaderConfig structure
			var headerConfig HeaderConfig
			if err := mapstructure.Decode(v, &headerConfig); err == nil {
				if headerConfig.IsSecret {
					decoded, err := base64.StdEncoding.DecodeString(headerConfig.Value)
					if err != nil {
						result[key] = headerConfig.Value
					} else {
						result[key] = string(decoded)
					}
				} else {
					result[key] = headerConfig.Value
				}
			}
		default:
			result[key] = fmt.Sprintf("%v", v)
		}
	}
	return result
}

// EncryptSecrets encodes secret header values with base64 before storing in database
func (c *Credentials) EncryptSecrets() error {
	if c.Headers == nil {
		return nil
	}

	for key, val := range c.Headers {
		if headerMap, ok := val.(map[string]interface{}); ok {
			var headerConfig HeaderConfig
			if err := mapstructure.Decode(headerMap, &headerConfig); err == nil {
				if headerConfig.IsSecret && headerConfig.Value != "" {
					if _, err := base64.StdEncoding.DecodeString(headerConfig.Value); err != nil {
						encoded := base64.StdEncoding.EncodeToString([]byte(headerConfig.Value))
						c.Headers[key] = map[string]interface{}{
							"value":     encoded,
							"is_secret": true,
						}
					}
				}
			}
		}
	}
	return nil
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

	validMethods := map[string]bool{"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true}

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
		if !validMethods[resourceConfig.API.Resources.Method] {
			return fmt.Errorf("invalid method %q for resources API endpoint in resource type %s, must be one of: GET, POST, PUT, DELETE, PATCH", resourceConfig.API.Resources.Method, resource.Type)
		}

		if resourceConfig.API.Grant.Path == "" || resourceConfig.API.Grant.Method == "" {
			return fmt.Errorf("grant API endpoint (path, method) is required for resource type: %s", resource.Type)
		}
		if !validMethods[resourceConfig.API.Grant.Method] {
			return fmt.Errorf("invalid method %q for grant API endpoint in resource type %s, must be one of: GET, POST, PUT, DELETE, PATCH", resourceConfig.API.Grant.Method, resource.Type)
		}

		if resourceConfig.API.Revoke.Path == "" || resourceConfig.API.Revoke.Method == "" {
			return fmt.Errorf("revoke API endpoint (path, method) is required for resource type: %s", resource.Type)
		}
		if !validMethods[resourceConfig.API.Revoke.Method] {
			return fmt.Errorf("invalid method %q for revoke API endpoint in resource type %s, must be one of: GET, POST, PUT, DELETE, PATCH", resourceConfig.API.Revoke.Method, resource.Type)
		}
	}

	return nil
}
