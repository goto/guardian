package custom_http

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goto/guardian/pkg/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBasicTypes(t *testing.T) {
	t.Run("Credentials GetHeaders with string values", func(t *testing.T) {
		creds := Credentials{
			Headers: map[string]interface{}{
				"Authorization": "Bearer token",
				"X-API-Key":     "simple-key",
			},
		}
		headers := creds.GetHeaders()
		assert.Equal(t, "Bearer token", headers["Authorization"])
		assert.Equal(t, "simple-key", headers["X-API-Key"])
	})

	t.Run("Credentials GetHeaders with secret header", func(t *testing.T) {
		// Simulate a base64-encoded secret stored in the database
		encodedSecret := base64.StdEncoding.EncodeToString([]byte("my-secret-token"))
		creds := Credentials{
			Headers: map[string]interface{}{
				"Authorization": map[string]interface{}{
					"value":     encodedSecret,
					"is_secret": true,
				},
			},
		}
		headers := creds.GetHeaders()
		// Should be decoded back to original value
		assert.Equal(t, "my-secret-token", headers["Authorization"])
	})

	t.Run("Credentials GetHeaders with non-secret header config", func(t *testing.T) {
		creds := Credentials{
			Headers: map[string]interface{}{
				"X-API-Key": map[string]interface{}{
					"value":     "plain-key",
					"is_secret": false,
				},
			},
		}
		headers := creds.GetHeaders()
		assert.Equal(t, "plain-key", headers["X-API-Key"])
	})

	t.Run("Credentials GetHeaders with mixed header types", func(t *testing.T) {
		// Simulate a base64-encoded secret stored in the database
		encodedSecret := base64.StdEncoding.EncodeToString([]byte("secret-token"))
		creds := Credentials{
			Headers: map[string]interface{}{
				"Authorization": map[string]interface{}{
					"value":     encodedSecret,
					"is_secret": true,
				},
				"X-API-Key":    "plain-key",
				"Content-Type": "application/json",
			},
		}
		headers := creds.GetHeaders()
		// Secret should be decoded back to original value
		assert.Equal(t, "secret-token", headers["Authorization"])
		assert.Equal(t, "plain-key", headers["X-API-Key"])
		assert.Equal(t, "application/json", headers["Content-Type"])
	})

	t.Run("Credentials GetHeaders with invalid base64 secret", func(t *testing.T) {
		// If decoding fails, should use value as-is
		creds := Credentials{
			Headers: map[string]interface{}{
				"Authorization": map[string]interface{}{
					"value":     "not-valid-base64!@#",
					"is_secret": true,
				},
			},
		}
		headers := creds.GetHeaders()
		// Should fallback to the original value
		assert.Equal(t, "not-valid-base64!@#", headers["Authorization"])
	})

	t.Run("Credentials GetHeaders nil", func(t *testing.T) {
		creds := Credentials{}
		headers := creds.GetHeaders()
		assert.NotNil(t, headers)
		assert.Empty(t, headers)
	})
}

func TestCredentials_EncryptSecrets(t *testing.T) {
	t.Run("should encrypt plain text secrets", func(t *testing.T) {
		creds := Credentials{
			Headers: map[string]interface{}{
				"Authorization": map[string]interface{}{
					"value":     "plain-secret-token",
					"is_secret": true,
				},
				"X-API-Key": "plain-value",
			},
		}

		err := creds.EncryptSecrets()
		require.NoError(t, err)

		// Check that secret was encoded
		authHeader := creds.Headers["Authorization"].(map[string]interface{})
		encodedValue := authHeader["value"].(string)

		// Decode and verify
		decoded, err := base64.StdEncoding.DecodeString(encodedValue)
		require.NoError(t, err)
		assert.Equal(t, "plain-secret-token", string(decoded))

		// Non-secret should remain unchanged
		assert.Equal(t, "plain-value", creds.Headers["X-API-Key"])
	})

	t.Run("should not re-encode already base64 encoded secrets", func(t *testing.T) {
		alreadyEncoded := base64.StdEncoding.EncodeToString([]byte("my-secret"))
		creds := Credentials{
			Headers: map[string]interface{}{
				"Authorization": map[string]interface{}{
					"value":     alreadyEncoded,
					"is_secret": true,
				},
			},
		}

		err := creds.EncryptSecrets()
		require.NoError(t, err)

		// Should remain the same
		authHeader := creds.Headers["Authorization"].(map[string]interface{})
		assert.Equal(t, alreadyEncoded, authHeader["value"])
	})

	t.Run("should handle nil headers", func(t *testing.T) {
		creds := Credentials{}
		err := creds.EncryptSecrets()
		assert.NoError(t, err)
	})

	t.Run("should handle non-secret headers", func(t *testing.T) {
		creds := Credentials{
			Headers: map[string]interface{}{
				"Content-Type": map[string]interface{}{
					"value":     "application/json",
					"is_secret": false,
				},
			},
		}

		err := creds.EncryptSecrets()
		require.NoError(t, err)

		// Should not be encoded
		header := creds.Headers["Content-Type"].(map[string]interface{})
		assert.Equal(t, "application/json", header["value"])
	})
}

func TestResourceMapping(t *testing.T) {
	mapping := ResourceMapping{
		ID:   "id",
		Name: "name",
		Type: "type",
	}

	assert.Equal(t, "id", mapping.ID)
	assert.Equal(t, "name", mapping.Name)
	assert.Equal(t, "type", mapping.Type)
}

func TestAPIEndpoint(t *testing.T) {
	endpoint := APIEndpoint{
		Path:   "/test",
		Method: "GET",
		Body: map[string]interface{}{
			"key": "value",
		},
	}

	assert.Equal(t, "/test", endpoint.Path)
	assert.Equal(t, "GET", endpoint.Method)
	assert.Equal(t, "value", endpoint.Body["key"])
}

func TestAPIConfiguration(t *testing.T) {
	config := APIConfiguration{
		Resources: APIEndpoint{
			Path:   "/resources",
			Method: "GET",
		},
		Grant: APIEndpoint{
			Path:   "/grant",
			Method: "POST",
		},
		Revoke: APIEndpoint{
			Path:   "/revoke",
			Method: "DELETE",
		},
	}

	assert.Equal(t, "/resources", config.Resources.Path)
	assert.Equal(t, "GET", config.Resources.Method)
	assert.Equal(t, "/grant", config.Grant.Path)
	assert.Equal(t, "POST", config.Grant.Method)
	assert.Equal(t, "/revoke", config.Revoke.Path)
	assert.Equal(t, "DELETE", config.Revoke.Method)
}

func TestNewClient(t *testing.T) {
	creds := Credentials{
		BaseURL: "https://api.example.com",
	}
	config := ProviderConfiguration{
		ResourceTypes: map[string]ResourceTypeConfiguration{},
	}
	logger := log.NewNoop()

	client := NewClient(creds, config, logger)

	assert.NotNil(t, client)
	assert.Equal(t, creds, client.credentials)
	assert.Equal(t, config, client.config)
	assert.NotNil(t, client.httpClient)
	assert.NotNil(t, client.logger)
}

func TestClient_GetResources(t *testing.T) {
	tests := []struct {
		name           string
		resourceType   string
		serverResponse interface{}
		statusCode     int
		config         ProviderConfiguration
		wantErr        bool
		errContains    string
		validateResult func(t *testing.T, resources []*Resource)
	}{
		{
			name:         "successful get resources with array response",
			resourceType: "project",
			serverResponse: []map[string]interface{}{
				{"id": "proj-1", "name": "Project 1"},
				{"id": "proj-2", "name": "Project 2"},
			},
			statusCode: http.StatusOK,
			config: ProviderConfiguration{
				ResourceTypes: map[string]ResourceTypeConfiguration{
					"project": {
						API: APIConfiguration{
							Resources: APIEndpoint{Path: "/projects", Method: "GET"},
							Grant:     APIEndpoint{Path: "/grant", Method: "POST"},
							Revoke:    APIEndpoint{Path: "/revoke", Method: "DELETE"},
						},
						ResourceMapping: ResourceMapping{ID: "id", Name: "name"},
					},
				},
			},
			wantErr: false,
			validateResult: func(t *testing.T, resources []*Resource) {
				t.Helper()
				require.Len(t, resources, 2)
				assert.Equal(t, "proj-1", resources[0].ID)
				assert.Equal(t, "Project 1", resources[0].Name)
				assert.Equal(t, "project", resources[0].Type)
			},
		},
		{
			name:         "successful get resources with wrapped response",
			resourceType: "project",
			serverResponse: map[string]interface{}{
				"data": []map[string]interface{}{
					{"id": "proj-1", "name": "Project 1"},
				},
			},
			statusCode: http.StatusOK,
			config: ProviderConfiguration{
				ResourceTypes: map[string]ResourceTypeConfiguration{
					"project": {
						API: APIConfiguration{
							Resources: APIEndpoint{Path: "/projects", Method: "GET"},
							Grant:     APIEndpoint{Path: "/grant", Method: "POST"},
							Revoke:    APIEndpoint{Path: "/revoke", Method: "DELETE"},
						},
						ResourceMapping: ResourceMapping{ID: "id", Name: "name"},
					},
				},
			},
			wantErr: false,
			validateResult: func(t *testing.T, resources []*Resource) {
				t.Helper()
				require.Len(t, resources, 1)
				assert.Equal(t, "proj-1", resources[0].ID)
			},
		},
		{
			name:         "error - resource type not configured",
			resourceType: "unknown",
			statusCode:   http.StatusOK,
			config: ProviderConfiguration{
				ResourceTypes: map[string]ResourceTypeConfiguration{},
			},
			wantErr:     true,
			errContains: "no configuration found for resource type",
		},
		{
			name:           "error - API returns non-200 status",
			resourceType:   "project",
			serverResponse: map[string]interface{}{"error": "not found"},
			statusCode:     http.StatusNotFound,
			config: ProviderConfiguration{
				ResourceTypes: map[string]ResourceTypeConfiguration{
					"project": {
						API: APIConfiguration{
							Resources: APIEndpoint{Path: "/projects", Method: "GET"},
							Grant:     APIEndpoint{Path: "/grant", Method: "POST"},
							Revoke:    APIEndpoint{Path: "/revoke", Method: "DELETE"},
						},
						ResourceMapping: ResourceMapping{ID: "id", Name: "name"},
					},
				},
			},
			wantErr:     true,
			errContains: "API returned status 404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				if tt.serverResponse != nil {
					json.NewEncoder(w).Encode(tt.serverResponse)
				}
			}))
			defer server.Close()

			creds := Credentials{
				BaseURL: server.URL,
				Headers: map[string]interface{}{
					"Authorization": "Bearer test-token",
				},
			}
			client := NewClient(creds, tt.config, log.NewNoop())

			resources, err := client.GetResources(context.Background(), tt.resourceType)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				if tt.validateResult != nil {
					tt.validateResult(t, resources)
				}
			}
		})
	}
}

func TestClient_GrantAccess(t *testing.T) {
	tests := []struct {
		name        string
		resource    *Resource
		accountID   string
		role        string
		statusCode  int
		config      ProviderConfiguration
		wantErr     bool
		errContains string
		validateReq func(t *testing.T, r *http.Request)
	}{
		{
			name: "successful grant access",
			resource: &Resource{
				ID:   "proj-1",
				Name: "Project 1",
				Type: "project",
				Details: map[string]interface{}{
					"id": "proj-1",
				},
			},
			accountID:  "user@example.com",
			role:       "viewer",
			statusCode: http.StatusOK,
			config: ProviderConfiguration{
				ResourceTypes: map[string]ResourceTypeConfiguration{
					"project": {
						API: APIConfiguration{
							Resources: APIEndpoint{Path: "/projects", Method: "GET"},
							Grant: APIEndpoint{
								Path:   "/projects/{{.resource_id}}/members",
								Method: "POST",
								Body: map[string]interface{}{
									"user_id": "{{.account_id}}",
									"role":    "{{.role}}",
								},
							},
							Revoke: APIEndpoint{Path: "/revoke", Method: "DELETE"},
						},
						ResourceMapping: ResourceMapping{ID: "id", Name: "name"},
						TemplateVariables: map[string]string{
							"resource_id": "{{.resource.Details.id}}",
							"account_id":  "{{.account_id}}",
							"role":        "{{.role}}",
						},
					},
				},
			},
			wantErr: false,
			validateReq: func(t *testing.T, r *http.Request) {
				t.Helper()
				assert.Equal(t, "POST", r.Method)
				assert.Contains(t, r.URL.Path, "/projects/proj-1/members")
			},
		},
		{
			name: "error - API returns error status",
			resource: &Resource{
				ID:   "proj-1",
				Name: "Project 1",
				Type: "project",
				Details: map[string]interface{}{
					"id": "proj-1",
				},
			},
			accountID:  "user@example.com",
			role:       "viewer",
			statusCode: http.StatusForbidden,
			config: ProviderConfiguration{
				ResourceTypes: map[string]ResourceTypeConfiguration{
					"project": {
						API: APIConfiguration{
							Resources: APIEndpoint{Path: "/projects", Method: "GET"},
							Grant: APIEndpoint{
								Path:   "/projects/{{.resource_id}}/members",
								Method: "POST",
							},
							Revoke: APIEndpoint{Path: "/revoke", Method: "DELETE"},
						},
						ResourceMapping: ResourceMapping{ID: "id", Name: "name"},
						TemplateVariables: map[string]string{
							"resource_id": "{{.resource.Details.id}}",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "403",
		},
		{
			name: "error - resource type not configured",
			resource: &Resource{
				ID:   "proj-1",
				Type: "unknown",
			},
			accountID:  "user@example.com",
			role:       "viewer",
			statusCode: http.StatusOK,
			config: ProviderConfiguration{
				ResourceTypes: map[string]ResourceTypeConfiguration{},
			},
			wantErr:     true,
			errContains: "no configuration found for resource type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.validateReq != nil {
					tt.validateReq(t, r)
				}
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			creds := Credentials{
				BaseURL: server.URL,
			}
			client := NewClient(creds, tt.config, log.NewNoop())

			err := client.GrantAccess(context.Background(), tt.resource, tt.accountID, tt.role)

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

func TestClient_RevokeAccess(t *testing.T) {
	tests := []struct {
		name        string
		resource    *Resource
		accountID   string
		role        string
		statusCode  int
		config      ProviderConfiguration
		wantErr     bool
		errContains string
		validateReq func(t *testing.T, r *http.Request)
	}{
		{
			name: "successful revoke access",
			resource: &Resource{
				ID:   "proj-1",
				Name: "Project 1",
				Type: "project",
				Details: map[string]interface{}{
					"id": "proj-1",
				},
			},
			accountID:  "user@example.com",
			role:       "viewer",
			statusCode: http.StatusOK,
			config: ProviderConfiguration{
				ResourceTypes: map[string]ResourceTypeConfiguration{
					"project": {
						API: APIConfiguration{
							Resources: APIEndpoint{Path: "/projects", Method: "GET"},
							Grant:     APIEndpoint{Path: "/grant", Method: "POST"},
							Revoke: APIEndpoint{
								Path:   "/projects/{{.resource_id}}/members/{{.account_id}}",
								Method: "DELETE",
							},
						},
						ResourceMapping: ResourceMapping{ID: "id", Name: "name"},
						TemplateVariables: map[string]string{
							"resource_id": "{{.resource.Details.id}}",
							"account_id":  "{{.account_id}}",
						},
					},
				},
			},
			wantErr: false,
			validateReq: func(t *testing.T, r *http.Request) {
				t.Helper()
				assert.Equal(t, "DELETE", r.Method)
				assert.Contains(t, r.URL.Path, "/projects/proj-1/members/user@example.com")
			},
		},
		{
			name: "error - API returns error status",
			resource: &Resource{
				ID:   "proj-1",
				Type: "project",
				Details: map[string]interface{}{
					"id": "proj-1",
				},
			},
			accountID:  "user@example.com",
			role:       "viewer",
			statusCode: http.StatusInternalServerError,
			config: ProviderConfiguration{
				ResourceTypes: map[string]ResourceTypeConfiguration{
					"project": {
						API: APIConfiguration{
							Resources: APIEndpoint{Path: "/projects", Method: "GET"},
							Grant:     APIEndpoint{Path: "/grant", Method: "POST"},
							Revoke:    APIEndpoint{Path: "/revoke", Method: "DELETE"},
						},
						ResourceMapping: ResourceMapping{ID: "id", Name: "name"},
					},
				},
			},
			wantErr:     true,
			errContains: "500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.validateReq != nil {
					tt.validateReq(t, r)
				}
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			creds := Credentials{
				BaseURL: server.URL,
			}
			client := NewClient(creds, tt.config, log.NewNoop())

			err := client.RevokeAccess(context.Background(), tt.resource, tt.accountID, tt.role)

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

func TestClient_ExtractFieldValue(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name        string
		data        map[string]interface{}
		fieldPath   string
		expected    interface{}
		wantErr     bool
		errContains string
	}{
		{
			name: "simple field",
			data: map[string]interface{}{
				"id": "123",
			},
			fieldPath: "id",
			expected:  "123",
			wantErr:   false,
		},
		{
			name: "nested field",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"email": "test@example.com",
				},
			},
			fieldPath: "user.email",
			expected:  "test@example.com",
			wantErr:   false,
		},
		{
			name: "deeply nested field",
			data: map[string]interface{}{
				"level1": map[string]interface{}{
					"level2": map[string]interface{}{
						"level3": "value",
					},
				},
			},
			fieldPath: "level1.level2.level3",
			expected:  "value",
			wantErr:   false,
		},
		{
			name: "field not found",
			data: map[string]interface{}{
				"id": "123",
			},
			fieldPath:   "nonexistent",
			wantErr:     true,
			errContains: "not found in path",
		},
		{
			name: "nested field not found",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"name": "test",
				},
			},
			fieldPath:   "user.email",
			wantErr:     true,
			errContains: "not found in path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := client.extractFieldValue(tt.data, tt.fieldPath)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestClient_MapToResource(t *testing.T) {
	tests := []struct {
		name         string
		rawResource  map[string]interface{}
		resourceType string
		config       ProviderConfiguration
		expected     *Resource
		wantErr      bool
		errContains  string
	}{
		{
			name: "successful mapping with all fields",
			rawResource: map[string]interface{}{
				"id":          "proj-1",
				"name":        "Project 1",
				"description": "Test project",
			},
			resourceType: "project",
			config: ProviderConfiguration{
				ResourceTypes: map[string]ResourceTypeConfiguration{
					"project": {
						ResourceMapping: ResourceMapping{
							ID:      "id",
							Name:    "name",
							Details: []string{"description"},
						},
						API: APIConfiguration{
							Resources: APIEndpoint{Path: "/projects", Method: "GET"},
							Grant:     APIEndpoint{Path: "/grant", Method: "POST"},
							Revoke:    APIEndpoint{Path: "/revoke", Method: "DELETE"},
						},
					},
				},
			},
			expected: &Resource{
				ID:   "proj-1",
				Name: "Project 1",
				Type: "project",
				Details: map[string]interface{}{
					"description": "Test project",
				},
			},
			wantErr: false,
		},
		{
			name: "error - missing ID field",
			rawResource: map[string]interface{}{
				"name": "Project 1",
			},
			resourceType: "project",
			config: ProviderConfiguration{
				ResourceTypes: map[string]ResourceTypeConfiguration{
					"project": {
						ResourceMapping: ResourceMapping{
							ID:   "id",
							Name: "name",
						},
						API: APIConfiguration{
							Resources: APIEndpoint{Path: "/projects", Method: "GET"},
							Grant:     APIEndpoint{Path: "/grant", Method: "POST"},
							Revoke:    APIEndpoint{Path: "/revoke", Method: "DELETE"},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "extracting id field",
		},
		{
			name: "error - missing Name field",
			rawResource: map[string]interface{}{
				"id": "proj-1",
			},
			resourceType: "project",
			config: ProviderConfiguration{
				ResourceTypes: map[string]ResourceTypeConfiguration{
					"project": {
						ResourceMapping: ResourceMapping{
							ID:   "id",
							Name: "name",
						},
						API: APIConfiguration{
							Resources: APIEndpoint{Path: "/projects", Method: "GET"},
							Grant:     APIEndpoint{Path: "/grant", Method: "POST"},
							Revoke:    APIEndpoint{Path: "/revoke", Method: "DELETE"},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "extracting name field",
		},
		{
			name: "error - resource type not configured",
			rawResource: map[string]interface{}{
				"id":   "proj-1",
				"name": "Project 1",
			},
			resourceType: "unknown",
			config: ProviderConfiguration{
				ResourceTypes: map[string]ResourceTypeConfiguration{},
			},
			wantErr:     true,
			errContains: "no configuration found for resource type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(Credentials{}, tt.config, log.NewNoop())

			resource, err := client.mapToResource(tt.rawResource, tt.resourceType)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.ID, resource.ID)
				assert.Equal(t, tt.expected.Name, resource.Name)
				assert.Equal(t, tt.expected.Type, resource.Type)
				// Verify ID is stored in Details["id"]
				assert.Equal(t, resource.ID, resource.Details["id"])
				if tt.expected.Details != nil {
					for key, value := range tt.expected.Details {
						assert.Equal(t, value, resource.Details[key])
					}
				}
			}
		})
	}
}
