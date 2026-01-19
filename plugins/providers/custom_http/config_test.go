package custom_http

import (
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_ParseAndValidate(t *testing.T) {
	tests := []struct {
		name           string
		providerConfig *domain.ProviderConfig
		wantErr        bool
		errContains    string
	}{
		{
			name: "valid configuration",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url": "https://api.example.com",
					"headers": map[string]interface{}{
						"Authorization": "Bearer token",
					},
					"resource_routes": map[string]interface{}{
						"project": map[string]interface{}{
							"api": map[string]interface{}{
								"resources": map[string]interface{}{
									"method": "GET",
									"path":   "/projects",
								},
								"grant": map[string]interface{}{
									"method": "POST",
									"path":   "/projects/{{.project_id}}/members",
									"body": map[string]interface{}{
										"user_id": "{{.user_id}}",
									},
								},
								"revoke": map[string]interface{}{
									"method": "DELETE",
									"path":   "/projects/{{.project_id}}/members/{{.user_id}}",
								},
							},
							"resource_mapping": map[string]interface{}{
								"id":   "id",
								"name": "name",
								// type is optional since type comes from configuration context
							},
							"template_variables": map[string]interface{}{
								"project_id": "{{.resource.Details.id}}",
								"user_id":    "{{.account_id}}",
							},
						},
					},
				},
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid provider type",
			providerConfig: &domain.ProviderConfig{
				Type: "invalid_type",
			},
			wantErr:     true,
			errContains: "invalid provider type",
		},
		{
			name: "missing base_url",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"headers": map[string]interface{}{
						"Authorization": "Bearer token",
					},
				},
			},
			wantErr:     true,
			errContains: "base_url is required",
		},
		{
			name: "missing resource routes",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url": "https://api.example.com",
				},
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
				},
			},
			wantErr:     true,
			errContains: "no resource routes found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := NewConfig(tt.providerConfig)
			err := config.ParseAndValidate()

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCredentials_GetHeaders(t *testing.T) {
	tests := []struct {
		name     string
		creds    Credentials
		expected map[string]string
	}{
		{
			name: "returns headers when set",
			creds: Credentials{
				Headers: map[string]string{
					"Authorization": "Bearer token",
					"Content-Type":  "application/json",
				},
			},
			expected: map[string]string{
				"Authorization": "Bearer token",
				"Content-Type":  "application/json",
			},
		},
		{
			name:     "returns empty map when headers is nil",
			creds:    Credentials{},
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.creds.GetHeaders()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewConfig(t *testing.T) {
	pc := &domain.ProviderConfig{
		Type: "custom_http",
	}

	config := NewConfig(pc)
	assert.NotNil(t, config)
	assert.Equal(t, pc, config.ProviderConfig)
}
