package gate_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/plugins/providers/gate"
	"github.com/goto/guardian/plugins/providers/gate/mocks"
	"github.com/stretchr/testify/assert"
)

func TestGetType(t *testing.T) {
	providerType := "gate"
	p := gate.NewProvider(providerType, nil)

	actualType := p.GetType()
	assert.Equal(t, providerType, actualType)
}

func TestGetResources(t *testing.T) {
	t.Run("should return resources returned by gate APIs", func(t *testing.T) {
		mockCrypto := new(mocks.Encryptor)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			page := r.URL.Query().Get("page")
			var resBody string

			switch page {
			case "1":
				resBody = `[
					{
						"id": 1,
						"name": "test-group-1",
						"gid": 11,
						"created_at": "2024-01-01T01:01:01.000Z",
						"updated_at": "2024-01-01T01:01:01.000Z",
						"deleted_by": null,
						"deleted_at": null,
						"description": null
					}
				]`
			case "2":
				resBody = `[
					{
						"id": 2,
						"name": "test-group-2",
						"gid": 22,
						"created_at": "2024-01-01T01:01:01.000Z",
						"updated_at": "2024-01-01T01:01:01.000Z",
						"deleted_by": null,
						"deleted_at": null,
						"description": null
					}
				]`
			default:
				resBody = `[]`
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(resBody))
		}))
		providerConfig := &domain.ProviderConfig{
			Type: "gate",
			URN:  "gate.example.com",
			Credentials: map[string]any{
				"host":    ts.URL,
				"api_key": "encrypted-api-key",
			},
			Resources: []*domain.ResourceConfig{
				{Type: "group"},
			},
		}

		mockCrypto.EXPECT().Decrypt("encrypted-api-key").Return("decrypted-api-key", nil)
		expectedResources := []*domain.Resource{
			{
				ProviderType: providerConfig.Type,
				ProviderURN:  providerConfig.URN,
				Type:         gate.GroupResourceType,
				URN:          "1",
				Name:         "test-group-1",
				GlobalURN:    "urn:gate:gate.example.com:group:1",
			},
			{
				ProviderType: providerConfig.Type,
				ProviderURN:  providerConfig.URN,
				Type:         gate.GroupResourceType,
				URN:          "2",
				Name:         "test-group-2",
				GlobalURN:    "urn:gate:gate.example.com:group:2",
			},
		}

		p := gate.NewProvider(domain.ProviderTypeGate, mockCrypto)
		actualResources, err := p.GetResources(context.Background(), providerConfig)

		assert.NoError(t, err)
		assert.Equal(t, expectedResources, actualResources)
		mockCrypto.AssertExpectations(t)
	})
}
