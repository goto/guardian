package gcloudiam_test

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/plugins/providers/gcloudiam"
	"github.com/goto/guardian/plugins/providers/gcloudiam/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/api/iam/v1"
)

func TestCreateConfig(t *testing.T) {
	t.Run("should return error if error in credentials are invalid/mandatory fields are missing", func(t *testing.T) {
		providerURN := "test-URN"
		crypto := new(mocks.Encryptor)
		client := new(mocks.GcloudIamClient)
		p := gcloudiam.NewProvider("", crypto)
		p.Clients = map[string]gcloudiam.GcloudIamClient{
			providerURN: client,
		}

		testcases := []struct {
			pc   *domain.ProviderConfig
			name string
		}{
			{
				name: "invalid credentials struct",
				pc: &domain.ProviderConfig{
					Credentials: "invalid-credential-structure",
					Resources: []*domain.ResourceConfig{
						{
							Type: gcloudiam.ResourceTypeProject,
							Roles: []*domain.Role{
								{
									ID:          "role-1",
									Name:        "BigQuery",
									Permissions: []interface{}{"roles/bigquery.admin"},
								},
								{
									ID:          "role-2",
									Name:        "Api gateway",
									Permissions: []interface{}{"roles/apigateway.viewer"},
								},
							},
						},
					},
					URN: providerURN,
				},
			},
			{
				name: "empty mandatory credentials",
				pc: &domain.ProviderConfig{
					Credentials: gcloudiam.Credentials{
						ServiceAccountKey: "",
						ResourceName:      "",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: gcloudiam.ResourceTypeProject,
							Roles: []*domain.Role{
								{
									ID:          "role-1",
									Name:        "BigQuery",
									Permissions: []interface{}{"roles/bigquery.admin"},
								},
								{
									ID:          "role-2",
									Name:        "Api gateway",
									Permissions: []interface{}{"roles/apigateway.viewer"},
								},
							},
						},
					},
					URN: providerURN,
				},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				actualError := p.CreateConfig(tc.pc)
				assert.Error(t, actualError)
			})
		}
	})

	t.Run("should return error if there parse and valid config is invalid", func(t *testing.T) {
		providerURN := "test-URN"
		crypto := new(mocks.Encryptor)
		client := new(mocks.GcloudIamClient)
		p := gcloudiam.NewProvider("", crypto)
		p.Clients = map[string]gcloudiam.GcloudIamClient{
			providerURN: client,
		}

		testcases := []struct {
			name string
			pc   *domain.ProviderConfig
		}{
			{
				name: "empty resource config",
				pc: &domain.ProviderConfig{
					Credentials: gcloudiam.Credentials{
						ServiceAccountKey: base64.StdEncoding.EncodeToString([]byte("service-account-key-json")),
						ResourceName:      "projects/test-resource-name",
					},
				},
			},
			{
				name: "invalid resource type",
				pc: &domain.ProviderConfig{
					Credentials: gcloudiam.Credentials{
						ServiceAccountKey: base64.StdEncoding.EncodeToString([]byte("service-account-key-json")),
						ResourceName:      "projects/test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: "invalid resource type",
						},
					},
				},
			},
			{
				name: "duplicate resource types",
				pc: &domain.ProviderConfig{
					Credentials: gcloudiam.Credentials{
						ServiceAccountKey: base64.StdEncoding.EncodeToString([]byte("service-account-key-json")),
						ResourceName:      "projects/test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: gcloudiam.ResourceTypeProject,
						},
						{
							Type: gcloudiam.ResourceTypeProject,
						},
					},
				},
			},
			{
				name: "service_account resource type in organization-level provider",
				pc: &domain.ProviderConfig{
					Credentials: gcloudiam.Credentials{
						ServiceAccountKey: base64.StdEncoding.EncodeToString([]byte("service-account-key-json")),
						ResourceName:      "organizations/my-organization-id",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: gcloudiam.ResourceTypeServiceAccount,
						},
					},
					URN: providerURN,
				},
			},
			{
				name: "empty roles",
				pc: &domain.ProviderConfig{
					Credentials: gcloudiam.Credentials{
						ServiceAccountKey: base64.StdEncoding.EncodeToString([]byte("service-account-key-json")),
						ResourceName:      "projects/test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: gcloudiam.ResourceTypeProject,
						},
					},
				},
			},
		}

		for _, tc := range testcases {
			actualError := p.CreateConfig(tc.pc)
			assert.Error(t, actualError)
		}
	})

	t.Run("should return error if error in encrypting the credentials", func(t *testing.T) {
		providerURN := "test-provider-urn"
		crypto := new(mocks.Encryptor)
		client := new(mocks.GcloudIamClient)
		p := gcloudiam.NewProvider("", crypto)
		p.Clients = map[string]gcloudiam.GcloudIamClient{
			providerURN: client,
		}
		expectedError := errors.New("error in encrypting SAK")

		crypto.On("Encrypt", `{"type":"service_account"}`).Return("", expectedError)

		gCloudRolesList := []*iam.Role{
			{
				Name:        "roles/bigquery.admin",
				Title:       "BigQuery Admin",
				Description: "Administer all BigQuery resources and data",
			},
		}
		client.EXPECT().
			GetGrantableRoles(mock.AnythingOfType("*context.emptyCtx"), gcloudiam.ResourceTypeProject).
			Return(gCloudRolesList, nil).Once()

		pc := &domain.ProviderConfig{
			Resources: []*domain.ResourceConfig{
				{
					Type: gcloudiam.ResourceTypeProject,
					Roles: []*domain.Role{
						{
							ID:          "role-1",
							Name:        "BigQuery",
							Permissions: []interface{}{"roles/bigquery.admin"},
						},
					},
				},
			},
			Credentials: gcloudiam.Credentials{
				ServiceAccountKey: base64.StdEncoding.EncodeToString([]byte(`{"type":"service_account"}`)),
				ResourceName:      "projects/test-resource-name",
			},
			URN: providerURN,
		}

		actualError := p.CreateConfig(pc)

		assert.Equal(t, expectedError, actualError)
	})

	t.Run("should return nil error and create the config on success", func(t *testing.T) {
		providerURN := "test-URN"
		crypto := new(mocks.Encryptor)
		client := new(mocks.GcloudIamClient)
		p := gcloudiam.NewProvider("", crypto)
		p.Clients = map[string]gcloudiam.GcloudIamClient{
			providerURN: client,
		}

		gCloudRolesList := []*iam.Role{
			{
				Name:        "roles/bigquery.admin",
				Title:       "BigQuery Admin",
				Description: "Administer all BigQuery resources and data",
			},
		}
		client.EXPECT().
			GetGrantableRoles(mock.AnythingOfType("*context.emptyCtx"), gcloudiam.ResourceTypeProject).
			Return(gCloudRolesList, nil).Once()

		crypto.On("Encrypt", `{"type":"service_account"}`).Return(`{"type":"service_account"}`, nil)

		pc := &domain.ProviderConfig{
			Resources: []*domain.ResourceConfig{
				{
					Type: gcloudiam.ResourceTypeProject,
					Roles: []*domain.Role{
						{
							ID:          "role-1",
							Name:        "BigQuery",
							Permissions: []interface{}{"roles/bigquery.admin"},
						},
					},
				},
			},
			Credentials: gcloudiam.Credentials{
				ServiceAccountKey: base64.StdEncoding.EncodeToString([]byte(`{"type":"service_account"}`)),
				ResourceName:      "projects/test-resource-name",
			},
			URN: providerURN,
		}

		actualError := p.CreateConfig(pc)

		assert.NoError(t, actualError)
		crypto.AssertExpectations(t)
	})
}

func TestGetType(t *testing.T) {
	t.Run("should return provider type name", func(t *testing.T) {
		expectedTypeName := domain.ProviderTypeMetabase
		crypto := new(mocks.Encryptor)
		p := gcloudiam.NewProvider(expectedTypeName, crypto)

		actualTypeName := p.GetType()

		assert.Equal(t, expectedTypeName, actualTypeName)
	})
}

func TestGetResources(t *testing.T) {
	t.Run("should error when credentials are invalid", func(t *testing.T) {
		crypto := new(mocks.Encryptor)
		p := gcloudiam.NewProvider("", crypto)
		pc := &domain.ProviderConfig{
			Type:        domain.ProviderTypeGCloudIAM,
			URN:         "test-project-id",
			Credentials: "invalid-creds",
			Resources: []*domain.ResourceConfig{
				{Type: gcloudiam.ResourceTypeProject},
			},
		}

		actualResources, actualError := p.GetResources(pc)

		assert.Nil(t, actualResources)
		assert.Error(t, actualError)
	})

	t.Run("should check for valid roles in provider config and return project resource object", func(t *testing.T) {
		providerURN := "test-provider-urn"
		crypto := new(mocks.Encryptor)
		client := new(mocks.GcloudIamClient)
		p := gcloudiam.NewProvider("", crypto)
		p.Clients = map[string]gcloudiam.GcloudIamClient{
			providerURN: client,
		}

		gCloudRolesList := []*iam.Role{
			{
				Name:        "roles/bigquery.admin",
				Title:       "BigQuery Admin",
				Description: "Administer all BigQuery resources and data",
			},
			{
				Name:        "roles/apigateway.viewer",
				Title:       "ApiGateway Viewer",
				Description: "Read-only access to ApiGateway and related resources",
			},
		}
		client.EXPECT().
			GetGrantableRoles(mock.AnythingOfType("*context.emptyCtx"), gcloudiam.ResourceTypeProject).
			Return(gCloudRolesList, nil).Once()

		pc := &domain.ProviderConfig{
			Type: domain.ProviderTypeGCloudIAM,
			URN:  providerURN,
			Credentials: map[string]interface{}{
				"resource_name":     "project/test-resource-name",
				"ServiceAccountKey": "12345",
			},
			Resources: []*domain.ResourceConfig{
				{
					Type: gcloudiam.ResourceTypeProject,
					Roles: []*domain.Role{
						{
							ID:          "role-1",
							Name:        "BigQuery",
							Permissions: []interface{}{"roles/bigquery.admin"},
						},
						{
							ID:          "role-2",
							Name:        "Api gateway",
							Permissions: []interface{}{"roles/apigateway.viewer"},
						},
					},
				},
			},
		}

		expectedResources := []*domain.Resource{
			{
				ProviderType: pc.Type,
				ProviderURN:  pc.URN,
				Type:         gcloudiam.ResourceTypeProject,
				URN:          "project/test-resource-name",
				Name:         "project/test-resource-name - GCP IAM",
			},
		}

		actualResources, actualError := p.GetResources(pc)
		assert.Equal(t, expectedResources, actualResources)
		assert.Nil(t, actualError)
	})

	t.Run("should return organization resource object", func(t *testing.T) {
		providerURN := "test-provider-urn"
		crypto := new(mocks.Encryptor)
		client := new(mocks.GcloudIamClient)
		p := gcloudiam.NewProvider("", crypto)
		p.Clients = map[string]gcloudiam.GcloudIamClient{
			providerURN: client,
		}

		gCloudRolesList := []*iam.Role{
			{
				Name:        "roles/organisation.admin",
				Title:       "Organisation Admin",
				Description: "Administer all Organisation resources and data",
			},
		}
		client.EXPECT().
			GetGrantableRoles(mock.AnythingOfType("*context.emptyCtx"), gcloudiam.ResourceTypeOrganization).
			Return(gCloudRolesList, nil).Once()
		pc := &domain.ProviderConfig{
			Type: domain.ProviderTypeGCloudIAM,
			URN:  providerURN,
			Credentials: map[string]interface{}{
				"resource_name": "organization/test-resource-name",
			},
			Resources: []*domain.ResourceConfig{
				{
					Type: gcloudiam.ResourceTypeOrganization,
					Roles: []*domain.Role{
						{
							ID:          "role-1",
							Name:        "Organisation Admin",
							Permissions: []interface{}{"roles/organisation.admin"},
						},
					},
				},
			},
		}

		expectedResources := []*domain.Resource{
			{
				ProviderType: pc.Type,
				ProviderURN:  pc.URN,
				Type:         gcloudiam.ResourceTypeOrganization,
				URN:          "organization/test-resource-name",
				Name:         "organization/test-resource-name - GCP IAM",
			},
		}

		actualResources, actualError := p.GetResources(pc)

		assert.Equal(t, expectedResources, actualResources)
		assert.Nil(t, actualError)
	})
}

func TestGrantAccess(t *testing.T) {
	t.Run("should return error if credentials is invalid", func(t *testing.T) {
		crypto := new(mocks.Encryptor)
		p := gcloudiam.NewProvider("", crypto)

		pc := &domain.ProviderConfig{
			Credentials: "invalid-credentials",
			Resources: []*domain.ResourceConfig{
				{
					Type: "test-type",
				},
			},
		}
		a := domain.Grant{
			Resource: &domain.Resource{
				Type: "test-type",
			},
			Role: "test-role",
		}

		actualError := p.GrantAccess(pc, a)
		assert.Error(t, actualError)
	})

	t.Run("should return error if resource type is unknown", func(t *testing.T) {
		providerURN := "test-provider-urn"
		crypto := new(mocks.Encryptor)
		p := gcloudiam.NewProvider("", crypto)
		crypto.On("Decrypt", "c2VydmljZS1hY2NvdW50LWtleS1qc29u").Return(`{"type":"service_account"}`, nil) // tests the newIamClient when p.Clients is not initialised in the provider config
		expectedError := errors.New("invalid resource type")

		pc := &domain.ProviderConfig{
			URN: providerURN,
			Resources: []*domain.ResourceConfig{
				{
					Type: "test-type",
				},
			},
			Credentials: gcloudiam.Credentials{
				ServiceAccountKey: base64.StdEncoding.EncodeToString([]byte("service-account-key-json")),
				ResourceName:      "projects/test-resource-name",
			},
		}
		a := domain.Grant{
			Resource: &domain.Resource{
				Type: "test-type",
			},
			Role: "test-role",
		}

		actualError := p.GrantAccess(pc, a)

		assert.EqualError(t, actualError, expectedError.Error())
	})

	t.Run("should return error if there is an error in granting the access", func(t *testing.T) {
		providerURN := "test-provider-urn"
		expectedError := errors.New("client error")
		crypto := new(mocks.Encryptor)
		client := new(mocks.GcloudIamClient)
		p := gcloudiam.NewProvider("", crypto)
		p.Clients = map[string]gcloudiam.GcloudIamClient{
			providerURN: client,
		}
		client.On("GrantAccess", mock.Anything, mock.Anything, mock.Anything).Return(expectedError).Once()

		pc := &domain.ProviderConfig{
			Resources: []*domain.ResourceConfig{
				{
					Type: gcloudiam.ResourceTypeProject,
					Roles: []*domain.Role{
						{
							ID:          "role-1",
							Name:        "BigQuery",
							Permissions: []interface{}{"roles/bigquery.admin"},
						},
						{
							ID:          "role-2",
							Name:        "Api gateway",
							Permissions: []interface{}{"roles/apigateway.viewer"},
						},
					},
				},
			},
			URN: providerURN,
		}
		a := domain.Grant{
			Resource: &domain.Resource{
				Type: gcloudiam.ResourceTypeProject,
				URN:  "999",
				Name: "test-role",
			},
			Role:        "role-1",
			Permissions: []string{"roles/bigquery.admin"},
		}

		actualError := p.GrantAccess(pc, a)

		assert.EqualError(t, actualError, expectedError.Error())
	})

	t.Run("should return nil error if granting access is successful", func(t *testing.T) {
		providerURN := "test-provider-urn"
		crypto := new(mocks.Encryptor)
		client := new(mocks.GcloudIamClient)
		expectedRole := "role-1"
		expectedAccountType := "user"
		expectedAccountID := "test@email.com"
		expectedPermission := "roles/bigquery.admin"
		p := gcloudiam.NewProvider("", crypto)
		p.Clients = map[string]gcloudiam.GcloudIamClient{
			providerURN: client,
		}
		client.On("GrantAccess", expectedAccountType, expectedAccountID, expectedPermission).Return(nil).Once()

		pc := &domain.ProviderConfig{
			Resources: []*domain.ResourceConfig{
				{
					Type: gcloudiam.ResourceTypeProject,
					Roles: []*domain.Role{
						{
							ID:          "role-1",
							Name:        "BigQuery",
							Permissions: []interface{}{"roles/bigquery.admin"},
						},
						{
							ID:          "role-2",
							Name:        "Api gateway",
							Permissions: []interface{}{"roles/apigateway.viewer"},
						},
					},
				},
			},
			URN: providerURN,
		}
		a := domain.Grant{
			Resource: &domain.Resource{
				Type: gcloudiam.ResourceTypeProject,
				URN:  "test-role",
			},
			Role:        expectedRole,
			AccountType: expectedAccountType,
			AccountID:   expectedAccountID,
			ResourceID:  "999",
			ID:          "999",
			Permissions: []string{"roles/bigquery.admin"},
		}

		actualError := p.GrantAccess(pc, a)

		assert.Nil(t, actualError)
	})
}

func TestRevokeAccess(t *testing.T) {
	t.Run("should return error if resource type is unknown", func(t *testing.T) {
		providerURN := "test-provider-urn"
		crypto := new(mocks.Encryptor)
		client := new(mocks.GcloudIamClient)
		p := gcloudiam.NewProvider("", crypto)
		p.Clients = map[string]gcloudiam.GcloudIamClient{
			providerURN: client,
		}
		expectedError := errors.New("invalid resource type")

		pc := &domain.ProviderConfig{
			URN: providerURN,
			Resources: []*domain.ResourceConfig{
				{
					Type: "test-type",
				},
			},
		}
		a := domain.Grant{
			Resource: &domain.Resource{
				Type: "test-type",
			},
			Role: "test-role",
		}

		actualError := p.RevokeAccess(pc, a)

		assert.EqualError(t, actualError, expectedError.Error())
	})

	t.Run("should return error if there is an error in revoking the access", func(t *testing.T) {
		providerURN := "test-provider-urn"
		expectedError := errors.New("client error")
		crypto := new(mocks.Encryptor)
		client := new(mocks.GcloudIamClient)
		p := gcloudiam.NewProvider("", crypto)
		p.Clients = map[string]gcloudiam.GcloudIamClient{
			providerURN: client,
		}
		client.On("RevokeAccess", mock.Anything, mock.Anything, mock.Anything).Return(expectedError).Once()

		pc := &domain.ProviderConfig{
			Resources: []*domain.ResourceConfig{
				{
					Type: gcloudiam.ResourceTypeProject,
					Roles: []*domain.Role{
						{
							ID:          "role-1",
							Name:        "BigQuery",
							Permissions: []interface{}{"roles/bigquery.admin"},
						},
						{
							ID:          "role-2",
							Name:        "Api gateway",
							Permissions: []interface{}{"roles/apigateway.viewer"},
						},
					},
				},
			},
			URN: providerURN,
		}
		a := domain.Grant{
			Resource: &domain.Resource{
				Type: gcloudiam.ResourceTypeProject,
				URN:  "999",
				Name: "test-role",
			},
			Role:        "role-1",
			Permissions: []string{"roles/bigquery.admin"},
		}

		actualError := p.RevokeAccess(pc, a)

		assert.EqualError(t, actualError, expectedError.Error())
	})

	t.Run("should return nil error if revoking access is successful", func(t *testing.T) {
		providerURN := "test-provider-urn"
		crypto := new(mocks.Encryptor)
		client := new(mocks.GcloudIamClient)
		expectedRole := "role-1"
		expectedPermission := "roles/bigquery.admin"
		expectedAccountType := "user"
		expectedAccountID := "test@email.com"
		p := gcloudiam.NewProvider("", crypto)
		p.Clients = map[string]gcloudiam.GcloudIamClient{
			providerURN: client,
		}
		client.On("RevokeAccess", expectedAccountType, expectedAccountID, expectedPermission).Return(nil).Once()

		pc := &domain.ProviderConfig{
			Resources: []*domain.ResourceConfig{
				{
					Type: gcloudiam.ResourceTypeProject,
					Roles: []*domain.Role{
						{
							ID:          "role-1",
							Name:        "BigQuery",
							Permissions: []interface{}{"roles/bigquery.admin"},
						},
						{
							ID:          "role-2",
							Name:        "Api gateway",
							Permissions: []interface{}{"roles/apigateway.viewer"},
						},
					},
				},
			},
			URN: providerURN,
		}
		a := domain.Grant{
			Resource: &domain.Resource{
				Type: gcloudiam.ResourceTypeProject,
				URN:  "test-role",
			},
			Role:        expectedRole,
			AccountType: expectedAccountType,
			AccountID:   expectedAccountID,
			ResourceID:  "999",
			ID:          "999",
		}

		actualError := p.RevokeAccess(pc, a)

		assert.Nil(t, actualError)
	})
}

func TestGetRoles(t *testing.T) {
	t.Run("should return error if resource type is not project or organisation", func(t *testing.T) {
		expectedError := gcloudiam.ErrInvalidResourceType
		providerURN := "test-provider-urn"
		crypto := new(mocks.Encryptor)
		client := new(mocks.GcloudIamClient)
		p := gcloudiam.NewProvider("", crypto)
		p.Clients = map[string]gcloudiam.GcloudIamClient{
			providerURN: client,
		}

		pc := &domain.ProviderConfig{
			Resources: []*domain.ResourceConfig{
				{
					Type: gcloudiam.ResourceTypeProject,
				},
			},
			URN: providerURN,
		}

		_, actualError := p.GetRoles(pc, "not_proj_not_org")

		assert.Equal(t, expectedError, actualError)
	})

	t.Run("should get the expected roles and no error", func(t *testing.T) {
		providerURN := "test-provider-urn"
		crypto := new(mocks.Encryptor)
		client := new(mocks.GcloudIamClient)
		expectedRoles := []*domain.Role{
			{
				ID:          "role-1",
				Name:        "BigQuery",
				Permissions: []interface{}{"roles/bigquery.admin"},
			},
		}

		p := gcloudiam.NewProvider("", crypto)
		p.Clients = map[string]gcloudiam.GcloudIamClient{
			providerURN: client,
		}

		pc := &domain.ProviderConfig{
			Resources: []*domain.ResourceConfig{
				{
					Type: gcloudiam.ResourceTypeProject,
					Roles: []*domain.Role{
						{
							ID:          "role-1",
							Name:        "BigQuery",
							Permissions: []interface{}{"roles/bigquery.admin"},
						},
					},
				},
			},
			URN: providerURN,
		}

		actualRoles, actualError := p.GetRoles(pc, "project")

		assert.Equal(t, expectedRoles, actualRoles)
		assert.Nil(t, actualError)
		client.AssertExpectations(t)
	})
}

func TestGetPermissions(t *testing.T) {
	t.Run("should get the expected permissions and no error", func(t *testing.T) {
		providerURN := "test-provider-urn"
		crypto := new(mocks.Encryptor)
		client := new(mocks.GcloudIamClient)
		expectedPermissions := []interface{}{"roles/bigquery.admin"}

		p := gcloudiam.NewProvider("", crypto)
		p.Clients = map[string]gcloudiam.GcloudIamClient{
			providerURN: client,
		}

		pc := &domain.ProviderConfig{
			Resources: []*domain.ResourceConfig{
				{
					Type: gcloudiam.ResourceTypeProject,
					Roles: []*domain.Role{
						{
							ID:          "role-1",
							Name:        "BigQuery",
							Permissions: []interface{}{"roles/bigquery.admin"},
						},
					},
				},
			},
			URN: providerURN,
		}

		actualPermissions, actualError := p.GetPermissions(pc, "project", "role-1")

		assert.Equal(t, expectedPermissions, actualPermissions)
		assert.Nil(t, actualError)
		client.AssertExpectations(t)
	})
}

func TestGetAccountTypes(t *testing.T) {
	t.Run("should return the supported account types: user, serviceAccount", func(t *testing.T) {
		expectedAccountTypes := []string{"user", "serviceAccount", "group"}
		crypto := new(mocks.Encryptor)
		p := gcloudiam.NewProvider("", crypto)

		actualAccountTypes := p.GetAccountTypes()

		assert.Equal(t, expectedAccountTypes, actualAccountTypes)
	})
}
