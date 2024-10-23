package dataplex_test

import (
	"testing"

	"github.com/goto/guardian/plugins/providers/dataplex"
	"github.com/stretchr/testify/assert"
)

func TestNewPolicyTagClient(t *testing.T) {
	t.Run("should return error if credentials are invalid", func(t *testing.T) {
		invalidCredentials := []byte("invalid-credentials")

		actualClient, actualError := dataplex.NewPolicyTagClient("test-project", "test-location", invalidCredentials)

		assert.Nil(t, actualClient)
		assert.Error(t, actualError)
	})
}
