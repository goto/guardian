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
		{
			name: "missing configuration for resource type",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url": "https://api.example.com",
					"resource_routes": map[string]interface{}{
						"project": map[string]interface{}{
							"api": map[string]interface{}{
								"resources": map[string]interface{}{
									"method": "GET",
									"path":   "/projects",
								},
								"grant": map[string]interface{}{
									"method": "POST",
									"path":   "/grant",
								},
								"revoke": map[string]interface{}{
									"method": "DELETE",
									"path":   "/revoke",
								},
							},
							"resource_mapping": map[string]interface{}{
								"id":   "id",
								"name": "name",
							},
						},
					},
				},
				Resources: []*domain.ResourceConfig{
					{Type: "unknown_type"},
				},
			},
			wantErr:     true,
			errContains: "missing configuration for resource type",
		},
		{
			name: "missing mapping id field",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url": "https://api.example.com",
					"resource_routes": map[string]interface{}{
						"project": map[string]interface{}{
							"api": map[string]interface{}{
								"resources": map[string]interface{}{
									"method": "GET",
									"path":   "/projects",
								},
								"grant": map[string]interface{}{
									"method": "POST",
									"path":   "/grant",
								},
								"revoke": map[string]interface{}{
									"method": "DELETE",
									"path":   "/revoke",
								},
							},
							"resource_mapping": map[string]interface{}{
								"name": "name",
							},
						},
					},
				},
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
				},
			},
			wantErr:     true,
			errContains: "mapping fields (id, name) are required",
		},
		{
			name: "missing mapping name field",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url": "https://api.example.com",
					"resource_routes": map[string]interface{}{
						"project": map[string]interface{}{
							"api": map[string]interface{}{
								"resources": map[string]interface{}{
									"method": "GET",
									"path":   "/projects",
								},
								"grant": map[string]interface{}{
									"method": "POST",
									"path":   "/grant",
								},
								"revoke": map[string]interface{}{
									"method": "DELETE",
									"path":   "/revoke",
								},
							},
							"resource_mapping": map[string]interface{}{
								"id": "id",
							},
						},
					},
				},
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
				},
			},
			wantErr:     true,
			errContains: "mapping fields (id, name) are required",
		},
		{
			name: "missing resources API endpoint path",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url": "https://api.example.com",
					"resource_routes": map[string]interface{}{
						"project": map[string]interface{}{
							"api": map[string]interface{}{
								"resources": map[string]interface{}{
									"method": "GET",
								},
								"grant": map[string]interface{}{
									"method": "POST",
									"path":   "/grant",
								},
								"revoke": map[string]interface{}{
									"method": "DELETE",
									"path":   "/revoke",
								},
							},
							"resource_mapping": map[string]interface{}{
								"id":   "id",
								"name": "name",
							},
						},
					},
				},
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
				},
			},
			wantErr:     true,
			errContains: "resources API endpoint (path, method) is required",
		},
		{
			name: "missing resources API endpoint method",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url": "https://api.example.com",
					"resource_routes": map[string]interface{}{
						"project": map[string]interface{}{
							"api": map[string]interface{}{
								"resources": map[string]interface{}{
									"path": "/projects",
								},
								"grant": map[string]interface{}{
									"method": "POST",
									"path":   "/grant",
								},
								"revoke": map[string]interface{}{
									"method": "DELETE",
									"path":   "/revoke",
								},
							},
							"resource_mapping": map[string]interface{}{
								"id":   "id",
								"name": "name",
							},
						},
					},
				},
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
				},
			},
			wantErr:     true,
			errContains: "resources API endpoint (path, method) is required",
		},
		{
			name: "missing grant API endpoint path",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url": "https://api.example.com",
					"resource_routes": map[string]interface{}{
						"project": map[string]interface{}{
							"api": map[string]interface{}{
								"resources": map[string]interface{}{
									"method": "GET",
									"path":   "/projects",
								},
								"grant": map[string]interface{}{
									"method": "POST",
								},
								"revoke": map[string]interface{}{
									"method": "DELETE",
									"path":   "/revoke",
								},
							},
							"resource_mapping": map[string]interface{}{
								"id":   "id",
								"name": "name",
							},
						},
					},
				},
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
				},
			},
			wantErr:     true,
			errContains: "grant API endpoint (path, method) is required",
		},
		{
			name: "missing grant API endpoint method",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url": "https://api.example.com",
					"resource_routes": map[string]interface{}{
						"project": map[string]interface{}{
							"api": map[string]interface{}{
								"resources": map[string]interface{}{
									"method": "GET",
									"path":   "/projects",
								},
								"grant": map[string]interface{}{
									"path": "/grant",
								},
								"revoke": map[string]interface{}{
									"method": "DELETE",
									"path":   "/revoke",
								},
							},
							"resource_mapping": map[string]interface{}{
								"id":   "id",
								"name": "name",
							},
						},
					},
				},
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
				},
			},
			wantErr:     true,
			errContains: "grant API endpoint (path, method) is required",
		},
		{
			name: "missing revoke API endpoint path",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url": "https://api.example.com",
					"resource_routes": map[string]interface{}{
						"project": map[string]interface{}{
							"api": map[string]interface{}{
								"resources": map[string]interface{}{
									"method": "GET",
									"path":   "/projects",
								},
								"grant": map[string]interface{}{
									"method": "POST",
									"path":   "/grant",
								},
								"revoke": map[string]interface{}{
									"method": "DELETE",
								},
							},
							"resource_mapping": map[string]interface{}{
								"id":   "id",
								"name": "name",
							},
						},
					},
				},
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
				},
			},
			wantErr:     true,
			errContains: "revoke API endpoint (path, method) is required",
		},
		{
			name: "missing revoke API endpoint method",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url": "https://api.example.com",
					"resource_routes": map[string]interface{}{
						"project": map[string]interface{}{
							"api": map[string]interface{}{
								"resources": map[string]interface{}{
									"method": "GET",
									"path":   "/projects",
								},
								"grant": map[string]interface{}{
									"method": "POST",
									"path":   "/grant",
								},
								"revoke": map[string]interface{}{
									"path": "/revoke",
								},
							},
							"resource_mapping": map[string]interface{}{
								"id":   "id",
								"name": "name",
							},
						},
					},
				},
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
				},
			},
			wantErr:     true,
			errContains: "revoke API endpoint (path, method) is required",
		},
		{
			name: "invalid credentials - cannot decode",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url": []string{"not", "a", "string"}, // Invalid type
				},
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
				},
			},
			wantErr:     true,
			errContains: "invalid credentials format",
		},
		{
			name: "empty resource routes map",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url":        "https://api.example.com",
					"resource_routes": map[string]interface{}{},
				},
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
				},
			},
			wantErr:     true,
			errContains: "no resource routes found",
		},
		{
			name: "missing both id and name in mapping",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url": "https://api.example.com",
					"resource_routes": map[string]interface{}{
						"project": map[string]interface{}{
							"api": map[string]interface{}{
								"resources": map[string]interface{}{
									"method": "GET",
									"path":   "/projects",
								},
								"grant": map[string]interface{}{
									"method": "POST",
									"path":   "/grant",
								},
								"revoke": map[string]interface{}{
									"method": "DELETE",
									"path":   "/revoke",
								},
							},
							"resource_mapping": map[string]interface{}{
								"type": "project",
							},
						},
					},
				},
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
				},
			},
			wantErr:     true,
			errContains: "mapping fields (id, name) are required",
		},
		{
			name: "missing both path and method in resources endpoint",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url": "https://api.example.com",
					"resource_routes": map[string]interface{}{
						"project": map[string]interface{}{
							"api": map[string]interface{}{
								"resources": map[string]interface{}{},
								"grant": map[string]interface{}{
									"method": "POST",
									"path":   "/grant",
								},
								"revoke": map[string]interface{}{
									"method": "DELETE",
									"path":   "/revoke",
								},
							},
							"resource_mapping": map[string]interface{}{
								"id":   "id",
								"name": "name",
							},
						},
					},
				},
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
				},
			},
			wantErr:     true,
			errContains: "resources API endpoint (path, method) is required",
		},
		{
			name: "missing both path and method in grant endpoint",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url": "https://api.example.com",
					"resource_routes": map[string]interface{}{
						"project": map[string]interface{}{
							"api": map[string]interface{}{
								"resources": map[string]interface{}{
									"method": "GET",
									"path":   "/projects",
								},
								"grant": map[string]interface{}{},
								"revoke": map[string]interface{}{
									"method": "DELETE",
									"path":   "/revoke",
								},
							},
							"resource_mapping": map[string]interface{}{
								"id":   "id",
								"name": "name",
							},
						},
					},
				},
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
				},
			},
			wantErr:     true,
			errContains: "grant API endpoint (path, method) is required",
		},
		{
			name: "missing both path and method in revoke endpoint",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url": "https://api.example.com",
					"resource_routes": map[string]interface{}{
						"project": map[string]interface{}{
							"api": map[string]interface{}{
								"resources": map[string]interface{}{
									"method": "GET",
									"path":   "/projects",
								},
								"grant": map[string]interface{}{
									"method": "POST",
									"path":   "/grant",
								},
								"revoke": map[string]interface{}{},
							},
							"resource_mapping": map[string]interface{}{
								"id":   "id",
								"name": "name",
							},
						},
					},
				},
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
				},
			},
			wantErr:     true,
			errContains: "revoke API endpoint (path, method) is required",
		},
		{
			name: "multiple resource types - one missing config",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url": "https://api.example.com",
					"resource_routes": map[string]interface{}{
						"project": map[string]interface{}{
							"api": map[string]interface{}{
								"resources": map[string]interface{}{
									"method": "GET",
									"path":   "/projects",
								},
								"grant": map[string]interface{}{
									"method": "POST",
									"path":   "/grant",
								},
								"revoke": map[string]interface{}{
									"method": "DELETE",
									"path":   "/revoke",
								},
							},
							"resource_mapping": map[string]interface{}{
								"id":   "id",
								"name": "name",
							},
						},
					},
				},
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
					{Type: "dataset"}, // This one is missing
				},
			},
			wantErr:     true,
			errContains: "missing configuration for resource type: dataset",
		},
		{
			name: "valid config with multiple resource types",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url": "https://api.example.com",
					"resource_routes": map[string]interface{}{
						"project": map[string]interface{}{
							"api": map[string]interface{}{
								"resources": map[string]interface{}{
									"method": "GET",
									"path":   "/projects",
								},
								"grant": map[string]interface{}{
									"method": "POST",
									"path":   "/grant",
								},
								"revoke": map[string]interface{}{
									"method": "DELETE",
									"path":   "/revoke",
								},
							},
							"resource_mapping": map[string]interface{}{
								"id":   "id",
								"name": "name",
							},
						},
						"dataset": map[string]interface{}{
							"api": map[string]interface{}{
								"resources": map[string]interface{}{
									"method": "GET",
									"path":   "/datasets",
								},
								"grant": map[string]interface{}{
									"method": "POST",
									"path":   "/datasets/grant",
								},
								"revoke": map[string]interface{}{
									"method": "DELETE",
									"path":   "/datasets/revoke",
								},
							},
							"resource_mapping": map[string]interface{}{
								"id":   "id",
								"name": "name",
							},
						},
					},
				},
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
					{Type: "dataset"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with optional details field",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url": "https://api.example.com",
					"resource_routes": map[string]interface{}{
						"project": map[string]interface{}{
							"api": map[string]interface{}{
								"resources": map[string]interface{}{
									"method": "GET",
									"path":   "/projects",
								},
								"grant": map[string]interface{}{
									"method": "POST",
									"path":   "/grant",
								},
								"revoke": map[string]interface{}{
									"method": "DELETE",
									"path":   "/revoke",
								},
							},
							"resource_mapping": map[string]interface{}{
								"id":      "id",
								"name":    "name",
								"details": []string{"description", "owner", "created_at"},
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
