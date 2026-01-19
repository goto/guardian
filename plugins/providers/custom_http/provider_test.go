package custom_http

import (
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
			name: "invalid configuration",
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

func TestNewProvider(t *testing.T) {
	p := NewProvider("custom_http", nil)
	assert.NotNil(t, p)
	assert.Equal(t, "custom_http", p.GetType())
}
