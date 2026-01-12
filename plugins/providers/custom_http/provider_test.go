package custom_http_test

import (
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/plugins/providers/custom_http"
	"github.com/stretchr/testify/assert"
)

func TestProvider_GetType(t *testing.T) {
	logger := log.NewNoop()
	provider := custom_http.NewProvider("custom_http", logger)

	assert.Equal(t, "custom_http", provider.GetType())
}

func TestProvider_GetAccountTypes(t *testing.T) {
	logger := log.NewNoop()
	provider := custom_http.NewProvider("custom_http", logger)

	accountTypes := provider.GetAccountTypes()
	expected := []string{"user", "serviceAccount"}

	assert.Equal(t, expected, accountTypes)
}

func TestProvider_CreateConfig(t *testing.T) {
	logger := log.NewNoop()
	provider := custom_http.NewProvider("custom_http", logger)

	t.Run("valid config", func(t *testing.T) {
		config := &domain.ProviderConfig{
			Type: "custom_http",
			URN:  "test_urn",
			Credentials: map[string]interface{}{
				"base_url": "https://api.example.com",
				"headers": map[string]string{
					"Authorization": "Bearer token123",
					"X-Client-ID":   "client123",
				},
			},
			Labels: map[string]string{
				"config": `{
					"api": {
						"resources": {"method": "GET", "path": "/api/v1/resources"},
						"grant": {"method": "POST", "path": "/api/v1/grant"},
						"revoke": {"method": "DELETE", "path": "/api/v1/revoke"}
					},
					"mapping": {
						"name": "name",
						"id": "id",
						"urn": "urn"
					}
				}`,
			},
			Resources: []*domain.ResourceConfig{
				{
					Type: "http_resource",
					Policy: &domain.PolicyConfig{
						ID:      "test_policy",
						Version: 1,
					},
				},
			},
		}

		err := provider.CreateConfig(config)
		assert.NoError(t, err)
	})

	t.Run("invalid type", func(t *testing.T) {
		config := &domain.ProviderConfig{
			Type: "invalid_type",
		}

		err := provider.CreateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid provider type")
	})

	t.Run("missing base_url", func(t *testing.T) {
		config := &domain.ProviderConfig{
			Type: "custom_http",
			Credentials: map[string]interface{}{
				"headers": map[string]string{},
			},
			Labels: map[string]string{
				"config": `{
					"api": {
						"resources": {"method": "GET", "path": "/api/v1/resources"},
						"grant": {"method": "POST", "path": "/api/v1/grant"},
						"revoke": {"method": "DELETE", "path": "/api/v1/revoke"}
					},
					"mapping": {
						"name": "name",
						"id": "id",
						"urn": "urn"
					}
				}`,
			},
			Resources: []*domain.ResourceConfig{
				{
					Type: "http_resource",
				},
			},
		}

		err := provider.CreateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "base_url is required")
	})

	t.Run("missing resources", func(t *testing.T) {
		config := &domain.ProviderConfig{
			Type: "custom_http",
			Credentials: map[string]interface{}{
				"base_url": "https://api.example.com",
			},
			Labels: map[string]string{
				"config": `{
					"api": {
						"resources": {"method": "GET", "path": "/api/v1/resources"},
						"grant": {"method": "POST", "path": "/api/v1/grant"},
						"revoke": {"method": "DELETE", "path": "/api/v1/revoke"}
					},
					"mapping": {
						"name": "name",
						"id": "id",
						"urn": "urn"
					}
				}`,
			},
			Resources: []*domain.ResourceConfig{},
		}

		err := provider.CreateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one resource configuration is required")
	})
}
