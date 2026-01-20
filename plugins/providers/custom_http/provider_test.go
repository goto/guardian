package custom_http

import (
	"context"
	"errors"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockHTTPClient is a mock implementation of HTTPClient
type MockHTTPClient struct {
	mock.Mock
}

func (m *MockHTTPClient) GetResources(ctx context.Context, resourceType string) ([]*Resource, error) {
	args := m.Called(ctx, resourceType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*Resource), args.Error(1)
}

func (m *MockHTTPClient) GrantAccess(ctx context.Context, resource *Resource, accountID, role string) error {
	args := m.Called(ctx, resource, accountID, role)
	return args.Error(0)
}

func (m *MockHTTPClient) RevokeAccess(ctx context.Context, resource *Resource, accountID, role string) error {
	args := m.Called(ctx, resource, accountID, role)
	return args.Error(0)
}

func TestProvider_CreateConfig(t *testing.T) {
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
								},
								"revoke": map[string]interface{}{
									"method": "DELETE",
									"path":   "/projects/{{.project_id}}/members/{{.user_id}}",
								},
							},
							"resource_mapping": map[string]interface{}{
								"id":   "id",
								"name": "name",
								"type": "type",
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
				Credentials: map[string]interface{}{
					"base_url": "https://api.example.com",
				},
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
				},
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
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
				},
			},
			wantErr:     true,
			errContains: "base_url is required",
		},
		{
			name: "no resource configurations",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url": "https://api.example.com",
				},
				Resources: []*domain.ResourceConfig{},
			},
			wantErr:     true,
			errContains: "at least one resource configuration is required",
		},
		{
			name: "invalid credentials format",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				Credentials: map[string]interface{}{
					"base_url": 12345, // Invalid type
				},
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
				},
			},
			wantErr:     true,
			errContains: "invalid provider credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{}
			err := p.CreateConfig(tt.providerConfig)

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

func TestProvider_GetType(t *testing.T) {
	p := NewProvider("custom_http", nil)
	assert.Equal(t, "custom_http", p.GetType())
}

func TestProvider_GetAccountTypes(t *testing.T) {
	p := NewProvider("custom_http", nil)
	accountTypes := p.GetAccountTypes()

	require.Len(t, accountTypes, 2)
	assert.Contains(t, accountTypes, "user")
	assert.Contains(t, accountTypes, "serviceAccount")
}

func TestNewProvider(t *testing.T) {
	logger := log.NewNoop()
	p := NewProvider("custom_http", logger)

	assert.NotNil(t, p)
	assert.Equal(t, "custom_http", p.GetType())
	assert.NotNil(t, p.Clients)
	assert.Empty(t, p.Clients)
	assert.Equal(t, logger, p.logger)
}

func TestProvider_GetResources(t *testing.T) {
	tests := []struct {
		name           string
		providerConfig *domain.ProviderConfig
		setupMock      func(*MockHTTPClient)
		wantErr        bool
		errContains    string
		validateResult func(t *testing.T, resources []*domain.Resource)
	}{
		{
			name: "successful get resources",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				URN:  "test-provider",
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
				},
			},
			setupMock: func(m *MockHTTPClient) {
				m.On("GetResources", mock.Anything, "project").Return([]*Resource{
					{
						ID:      "proj-1",
						Name:    "Project 1",
						Type:    "project",
						URN:     "proj-1",
						Details: map[string]interface{}{"id": "proj-1"},
					},
					{
						ID:      "proj-2",
						Name:    "Project 2",
						Type:    "project",
						URN:     "proj-2",
						Details: map[string]interface{}{"id": "proj-2"},
					},
				}, nil)
			},
			wantErr: false,
			validateResult: func(t *testing.T, resources []*domain.Resource) {
				t.Helper()
				require.Len(t, resources, 2)
				assert.Equal(t, "proj-1", resources[0].ID)
				assert.Equal(t, "Project 1", resources[0].Name)
				assert.Equal(t, "project", resources[0].Type)
				assert.Equal(t, "custom_http", resources[0].ProviderType)
				assert.Equal(t, "test-provider", resources[0].ProviderURN)
				assert.Contains(t, resources[0].GlobalURN, "custom_http:test-provider:project")
			},
		},
		{
			name: "error getting resources from client",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				URN:  "test-provider",
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
				},
			},
			setupMock: func(m *MockHTTPClient) {
				m.On("GetResources", mock.Anything, "project").Return(nil, errors.New("API error"))
			},
			wantErr:     true,
			errContains: "getting resources of type project from HTTP API",
		},
		{
			name: "error - invalid credentials",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				URN:  "test-provider",
				Credentials: map[string]interface{}{
					"base_url": 12345, // Invalid type
				},
				Resources: []*domain.ResourceConfig{
					{Type: "project"},
				},
			},
			setupMock: func(m *MockHTTPClient) {
				// No mock setup needed - error occurs before client is used
			},
			wantErr:     true,
			errContains: "invalid credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(MockHTTPClient)
			tt.setupMock(mockClient)

			p := NewProvider("custom_http", log.NewNoop())
			if tt.name == "successful get resources" || tt.name == "error getting resources from client" {
				p.Clients[tt.providerConfig.URN] = mockClient
			}

			resources, err := p.GetResources(context.Background(), tt.providerConfig)

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

			mockClient.AssertExpectations(t)
		})
	}
}

func TestProvider_GrantAccess(t *testing.T) {
	tests := []struct {
		name           string
		providerConfig *domain.ProviderConfig
		grant          domain.Grant
		setupMock      func(*MockHTTPClient)
		wantErr        bool
		errContains    string
	}{
		{
			name: "successful grant access",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				URN:  "test-provider",
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
			},
			grant: domain.Grant{
				AccountID: "user@example.com",
				Role:      "viewer",
				Resource: &domain.Resource{
					ID:   "proj-1",
					Name: "Project 1",
					Type: "project",
					URN:  "proj-1",
					Details: map[string]interface{}{
						"id": "proj-1",
					},
				},
			},
			setupMock: func(m *MockHTTPClient) {
				m.On("GrantAccess", mock.Anything, mock.AnythingOfType("*custom_http.Resource"), "user@example.com", "viewer").Return(nil)
			},
			wantErr: false,
		},
		{
			name: "error from client",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				URN:  "test-provider",
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
			},
			grant: domain.Grant{
				AccountID: "user@example.com",
				Role:      "viewer",
				Resource: &domain.Resource{
					ID:   "proj-1",
					Name: "Project 1",
					Type: "project",
					URN:  "proj-1",
					Details: map[string]interface{}{
						"id": "proj-1",
					},
				},
			},
			setupMock: func(m *MockHTTPClient) {
				m.On("GrantAccess", mock.Anything, mock.AnythingOfType("*custom_http.Resource"), "user@example.com", "viewer").Return(errors.New("API error"))
			},
			wantErr:     true,
			errContains: "granting access via HTTP API",
		},
		{
			name: "error - invalid credentials",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				URN:  "test-provider",
				Credentials: map[string]interface{}{
					"base_url": 12345,
				},
			},
			grant: domain.Grant{
				AccountID: "user@example.com",
				Role:      "viewer",
				Resource: &domain.Resource{
					ID:   "proj-1",
					Type: "project",
				},
			},
			setupMock: func(m *MockHTTPClient) {
				// No mock setup - error occurs before client is used
			},
			wantErr:     true,
			errContains: "invalid credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(MockHTTPClient)
			tt.setupMock(mockClient)

			p := NewProvider("custom_http", log.NewNoop())
			if tt.name == "successful grant access" || tt.name == "error from client" {
				p.Clients[tt.providerConfig.URN] = mockClient
			}

			err := p.GrantAccess(context.Background(), tt.providerConfig, tt.grant)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}

			mockClient.AssertExpectations(t)
		})
	}
}

func TestProvider_RevokeAccess(t *testing.T) {
	tests := []struct {
		name           string
		providerConfig *domain.ProviderConfig
		grant          domain.Grant
		setupMock      func(*MockHTTPClient)
		wantErr        bool
		errContains    string
	}{
		{
			name: "successful revoke access",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				URN:  "test-provider",
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
			},
			grant: domain.Grant{
				AccountID: "user@example.com",
				Role:      "viewer",
				Resource: &domain.Resource{
					ID:   "proj-1",
					Name: "Project 1",
					Type: "project",
					URN:  "proj-1",
					Details: map[string]interface{}{
						"id": "proj-1",
					},
				},
			},
			setupMock: func(m *MockHTTPClient) {
				m.On("RevokeAccess", mock.Anything, mock.AnythingOfType("*custom_http.Resource"), "user@example.com", "viewer").Return(nil)
			},
			wantErr: false,
		},
		{
			name: "error from client",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				URN:  "test-provider",
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
			},
			grant: domain.Grant{
				AccountID: "user@example.com",
				Role:      "viewer",
				Resource: &domain.Resource{
					ID:   "proj-1",
					Name: "Project 1",
					Type: "project",
					URN:  "proj-1",
					Details: map[string]interface{}{
						"id": "proj-1",
					},
				},
			},
			setupMock: func(m *MockHTTPClient) {
				m.On("RevokeAccess", mock.Anything, mock.AnythingOfType("*custom_http.Resource"), "user@example.com", "viewer").Return(errors.New("API error"))
			},
			wantErr:     true,
			errContains: "revoking access via HTTP API",
		},
		{
			name: "error - invalid credentials",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				URN:  "test-provider",
				Credentials: map[string]interface{}{
					"base_url": 12345,
				},
			},
			grant: domain.Grant{
				AccountID: "user@example.com",
				Role:      "viewer",
				Resource: &domain.Resource{
					ID:   "proj-1",
					Type: "project",
				},
			},
			setupMock: func(m *MockHTTPClient) {
				// No mock setup - error occurs before client is used
			},
			wantErr:     true,
			errContains: "invalid credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(MockHTTPClient)
			tt.setupMock(mockClient)

			p := NewProvider("custom_http", log.NewNoop())
			if tt.name == "successful revoke access" || tt.name == "error from client" {
				p.Clients[tt.providerConfig.URN] = mockClient
			}

			err := p.RevokeAccess(context.Background(), tt.providerConfig, tt.grant)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}

			mockClient.AssertExpectations(t)
		})
	}
}

func TestProvider_GetRoles(t *testing.T) {
	providerConfig := &domain.ProviderConfig{
		Type: "custom_http",
		URN:  "test-provider",
		Resources: []*domain.ResourceConfig{
			{
				Type: "project",
				Roles: []*domain.Role{
					{ID: "viewer", Name: "Viewer"},
					{ID: "editor", Name: "Editor"},
				},
			},
		},
	}

	p := NewProvider("custom_http", log.NewNoop())
	roles, err := p.GetRoles(providerConfig, "project")

	require.NoError(t, err)
	require.Len(t, roles, 2)
	assert.Equal(t, "viewer", roles[0].ID)
	assert.Equal(t, "Viewer", roles[0].Name)
	assert.Equal(t, "editor", roles[1].ID)
	assert.Equal(t, "Editor", roles[1].Name)
}

func TestProvider_GetClient(t *testing.T) {
	tests := []struct {
		name           string
		providerConfig *domain.ProviderConfig
		setupProvider  func(*Provider)
		wantErr        bool
		errContains    string
		verifyCached   bool
	}{
		{
			name: "creates new client",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				URN:  "new-provider",
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
			},
			setupProvider: func(p *Provider) {
				// No setup needed
			},
			wantErr: false,
		},
		{
			name: "returns cached client",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				URN:  "cached-provider",
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
			},
			setupProvider: func(p *Provider) {
				// Pre-populate cache
				mockClient := new(MockHTTPClient)
				p.Clients["cached-provider"] = mockClient
			},
			wantErr:      false,
			verifyCached: true,
		},
		{
			name: "error - invalid credentials",
			providerConfig: &domain.ProviderConfig{
				Type: "custom_http",
				URN:  "invalid-provider",
				Credentials: map[string]interface{}{
					"base_url": 12345, // Invalid type
				},
			},
			setupProvider: func(p *Provider) {
				// No setup needed
			},
			wantErr:     true,
			errContains: "invalid credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProvider("custom_http", log.NewNoop())
			tt.setupProvider(p)

			initialClientCount := len(p.Clients)
			client, err := p.getClient(tt.providerConfig)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, client)

				if tt.verifyCached {
					// Verify client count didn't increase (used cached)
					assert.Equal(t, initialClientCount, len(p.Clients))
				} else {
					// Verify client was added to cache
					assert.Equal(t, initialClientCount+1, len(p.Clients))
					assert.NotNil(t, p.Clients[tt.providerConfig.URN])
				}
			}
		})
	}
}
