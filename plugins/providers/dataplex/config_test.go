package dataplex_test

import (
	"encoding/base64"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/plugins/providers/dataplex"
	"github.com/stretchr/testify/assert"
)

func TestNewConfig(t *testing.T) {
	t.Run("should return dataplex config containing the same provider config", func(t *testing.T) {
		pc := &domain.ProviderConfig{}
		expectedProviderConfig := pc

		c := dataplex.NewConfig(pc)
		actualProviderConfig := c.ProviderConfig

		assert.NotNil(t, c)
		assert.Equal(t, expectedProviderConfig, actualProviderConfig)
	})
}

func TestValidate(t *testing.T) {
	validCredentials := dataplex.Credentials{
		ServiceAccountKey: base64.StdEncoding.EncodeToString([]byte("service-account-key-json")),
		ResourceName:      "projects/project-name/location/us",
	}
	credentialsWithoutBaseEncodedSAKey := dataplex.Credentials{
		ServiceAccountKey: "non-base64-value",
		ResourceName:      "projects/project-name/location/us",
	}
	credentialsWithoutResourceName := dataplex.Credentials{
		ServiceAccountKey: base64.StdEncoding.EncodeToString([]byte("service-account-key-json")),
	}
	validPermissionConfig := "permission-name"

	t.Run("error validations", func(t *testing.T) {
		testCases := []struct {
			name             string
			credentials      interface{}
			permissionConfig interface{}
		}{
			{
				name:             "should return error if service account key of credentials is not a base64 string",
				credentials:      credentialsWithoutBaseEncodedSAKey,
				permissionConfig: validPermissionConfig,
			},
			{
				name:             "should return error if permission type is invalid",
				credentials:      validCredentials,
				permissionConfig: 0,
			},
			{
				name:             "should return error if credentials config does not contain resource name field",
				credentials:      credentialsWithoutResourceName,
				permissionConfig: validPermissionConfig,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				pc := &domain.ProviderConfig{
					Credentials: tc.credentials,
					Resources: []*domain.ResourceConfig{
						{
							Roles: []*domain.Role{
								{
									Permissions: []interface{}{tc.permissionConfig},
								},
							},
						},
					},
				}

				err := dataplex.NewConfig(pc).ParseAndValidate()
				assert.Error(t, err)
			})
		}
	})

	/*t.Run("should update credentials and permission config values into castable bigquery config", func(t *testing.T) {
		pc := &domain.ProviderConfig{
			Credentials: validCredentials,
			Resources: []*domain.ResourceConfig{
				{
					Roles: []*domain.Role{
						{
							Permissions: []interface{}{validPermissionConfig},
						},
					},
				},
			},
		}
		mockCrypto.On("Encrypt", mock.Anything).Return("", nil).Once()

		err := bigquery.NewConfig(pc, mockCrypto).ParseAndValidate()
		_, credentialsOk := pc.Credentials.(*bigquery.Credentials)
		_, permissionConfigOk := pc.Resources[0].Roles[0].Permissions[0].(*bigquery.PermissionConfig)

		assert.Nil(t, err)
		assert.True(t, credentialsOk)
		assert.True(t, permissionConfigOk)
	})*/
}
