package custom_http

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBasicTypes(t *testing.T) {
	t.Run("Credentials GetHeaders", func(t *testing.T) {
		creds := Credentials{
			Headers: map[string]string{
				"Authorization": "Bearer token",
			},
		}
		headers := creds.GetHeaders()
		assert.Equal(t, "Bearer token", headers["Authorization"])
	})

	t.Run("Credentials GetHeaders nil", func(t *testing.T) {
		creds := Credentials{}
		headers := creds.GetHeaders()
		assert.NotNil(t, headers)
		assert.Empty(t, headers)
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
