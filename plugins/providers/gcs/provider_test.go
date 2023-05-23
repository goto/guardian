package gcs_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/plugins/providers/gcs"
	"github.com/goto/guardian/plugins/providers/gcs/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGetType(t *testing.T) {
	t.Run("should return the typeName of the provider", func(t *testing.T) {
		expectedTypeName := "test-typeName"
		p := gcs.NewProvider(expectedTypeName)

		actualTypeName := p.GetType()

		assert.Equal(t, expectedTypeName, actualTypeName)
	})
}

func TestCreateConfig(t *testing.T) {
	t.Run("should return error if error in parse and validate configurations", func(t *testing.T) {
		client := new(mocks.GCSClient)
		p := gcs.NewProvider("")
		p.Clients = map[string]gcs.GCSClient{
			"test-resource-name": client,
		}

		testcases := []struct {
			name string
			pc   *domain.ProviderConfig
		}{
			{
				name: "invalid resource type",
				pc: &domain.ProviderConfig{
					Credentials: gcs.Credentials{
						ServiceAccountKey: base64.StdEncoding.EncodeToString([]byte(`{"type":"service_account"}`)),
						ResourceName:      "projects/test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: "not dataset or table resource type",
							Roles: []*domain.Role{
								{
									ID:          "viewer",
									Permissions: []interface{}{"wrong permissions"},
								},
							},
						},
					},
				},
			},
			{
				name: "invalid permissions for bucket resource type",
				pc: &domain.ProviderConfig{
					Credentials: gcs.Credentials{
						ServiceAccountKey: base64.StdEncoding.EncodeToString([]byte(`{"type":"service_account"}`)),
						ResourceName:      "projects/test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: gcs.ResourceTypeBucket,
							Roles: []*domain.Role{
								{
									ID:          "viewer",
									Permissions: []interface{}{"wrong permissions"},
								},
							},
						},
					},
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

	t.Run("should make the provider config, parse and validate the credentials and permissions and return nil error on success", func(t *testing.T) {
		p := gcs.NewProvider("gcs")
		providerURN := "test-resource-name"
		pc := &domain.ProviderConfig{
			Type: domain.ProviderTypeGCS,
			URN:  providerURN,
			Credentials: gcs.Credentials{
				ServiceAccountKey: base64.StdEncoding.EncodeToString([]byte(`{"type":"service_account"}`)),
				ResourceName:      "projects/test-resource-name",
			},
			Resources: []*domain.ResourceConfig{
				{
					Type: gcs.ResourceTypeBucket,
					Roles: []*domain.Role{
						{
							ID:          "Storage Legacy Bucket Writer",
							Name:        "Storage Legacy Bucket Writer",
							Description: "Read access to buckets with object listing/creation/deletion",
							Permissions: []interface{}{"roles/storage.legacyBucketWriter"},
						},
					},
				},
			},
		}

		actualError := p.CreateConfig(pc)
		assert.NoError(t, actualError)
	})
}

func TestGetResources(t *testing.T) {
	t.Run("should return error if error in decoding credentials", func(t *testing.T) {
		p := initProvider()

		pc := &domain.ProviderConfig{
			Credentials: "invalid-credentials-struct",
			Resources: []*domain.ResourceConfig{
				{
					Type: "test-type",
					Roles: []*domain.Role{
						{
							ID:          "test-role",
							Permissions: []interface{}{"test-permission-config"},
						},
					},
				},
			},
		}
		actualResources, actualError := p.GetResources(pc)

		assert.Nil(t, actualResources)
		assert.Error(t, actualError)
	})

	t.Run("should get the bucket resources defined in the provider config", func(t *testing.T) {
		client := new(mocks.GCSClient)
		p := gcs.NewProvider("gcs")
		p.Clients = map[string]gcs.GCSClient{
			"test-resource-name": client,
		}
		providerURN := "test-resource-name"

		pc := &domain.ProviderConfig{
			Type: domain.ProviderTypeGCS,
			URN:  providerURN,
			Credentials: gcs.Credentials{
				ServiceAccountKey: base64.StdEncoding.EncodeToString([]byte("service_account-key-json")),
				ResourceName:      "projects/test-resource-name",
			},
			Resources: []*domain.ResourceConfig{
				{
					Type: gcs.ResourceTypeBucket,
					Roles: []*domain.Role{
						{
							ID:          "Storage Legacy Bucket Writer",
							Name:        "Storage Legacy Bucket Writer",
							Description: "Read access to buckets with object listing/creation/deletion",
							Permissions: []interface{}{"roles/storage.legacyBucketWriter"},
						},
					},
				},
			},
		}
		expectedBuckets := []*gcs.Bucket{
			{
				Name: "test-bucket-name",
			},
		}
		client.On("GetBuckets", mock.Anything).Return(expectedBuckets, nil).Once()
		expectedResources := []*domain.Resource{
			{
				ProviderType: pc.Type,
				ProviderURN:  pc.URN,
				Type:         gcs.ResourceTypeBucket,
				URN:          "test-bucket-name",
				Name:         "test-bucket-name",
			},
		}
		actualResources, actualError := p.GetResources(pc)

		assert.Equal(t, expectedResources, actualResources)
		assert.Nil(t, actualError)
		client.AssertExpectations(t)
	})
}

func TestGrantAccess(t *testing.T) {
	t.Run("should return error if Provider Config or Appeal doesn't have required parameters", func(t *testing.T) {
		testCases := []struct {
			name           string
			providerConfig *domain.ProviderConfig
			grant          domain.Grant
			expectedError  error
		}{
			{
				name:           "nil provider config",
				providerConfig: nil,
				expectedError:  fmt.Errorf("invalid provider/appeal config: %w", gcs.ErrNilProviderConfig),
			},
			{
				name: "nil resource config",
				providerConfig: &domain.ProviderConfig{
					Type:                domain.ProviderTypeGCS,
					URN:                 "test-URN",
					AllowedAccountTypes: []string{"user", "serviceAccount"},
				},
				grant: domain.Grant{
					ID:          "test-appeal-id",
					AccountType: "user",
				},
				expectedError: fmt.Errorf("invalid provider/appeal config: %w", gcs.ErrNilResource),
			},
			{
				name: "provider type doesnt match",
				providerConfig: &domain.ProviderConfig{
					Type:                domain.ProviderTypeGCS,
					URN:                 "test-URN-1",
					AllowedAccountTypes: []string{"user", "serviceAccount"},
				},
				grant: domain.Grant{
					ID:          "test-appeal-id",
					AccountType: "user",
					Resource: &domain.Resource{
						ID:           "test-resource-id",
						ProviderType: "not-gcs",
					},
				},
				expectedError: fmt.Errorf("invalid provider/appeal config: %w", gcs.ErrProviderTypeMismatch),
			},
			{
				name: "provider urn doesnt match",
				providerConfig: &domain.ProviderConfig{
					Type:                domain.ProviderTypeGCS,
					URN:                 "test-URN-1",
					AllowedAccountTypes: []string{"user", "serviceAccount"},
				},
				grant: domain.Grant{
					ID:          "test-appeal-id",
					AccountType: "user",
					Resource: &domain.Resource{
						ID:           "test-resource-id",
						ProviderType: domain.ProviderTypeGCS,
						ProviderURN:  "not-test-URN-1",
					},
				},
				expectedError: fmt.Errorf("invalid provider/appeal config: %w", gcs.ErrProviderURNMismatch),
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				p := initProvider()
				pc := tc.providerConfig
				g := tc.grant

				actualError := p.GrantAccess(pc, g)
				assert.EqualError(t, actualError, tc.expectedError.Error())
			})
		}
	})

	t.Run("should return error if error in decoding credentials", func(t *testing.T) {
		p := initProvider()

		pc := &domain.ProviderConfig{
			Credentials: "invalid-credentials-struct",
			Resources: []*domain.ResourceConfig{
				{
					Type: "test-type",
					Roles: []*domain.Role{
						{
							ID:          "test-role",
							Permissions: []interface{}{"test-permission-config"},
						},
					},
				},
			},
		}
		g := domain.Grant{
			Resource: &domain.Resource{
				Type: "test-type",
			},
			Role: "test-role",
		}
		actualError := p.GrantAccess(pc, g)
		assert.Error(t, actualError)
	})

	t.Run("should return error if error in getting the gcs client", func(t *testing.T) {
		expectedAccountType := "user"
		expectedAccountID := "test@email.com"
		p := gcs.NewProvider("gcs")
		providerURN := "test-resource-name"

		pc := &domain.ProviderConfig{
			Type: domain.ProviderTypeGCS,
			URN:  providerURN,
			Credentials: gcs.Credentials{
				ServiceAccountKey: base64.StdEncoding.EncodeToString([]byte("service_account-key-json")),
				ResourceName:      "projects/test-resource-name",
			},
			Resources: []*domain.ResourceConfig{
				{
					Type: gcs.ResourceTypeBucket,
					Roles: []*domain.Role{
						{
							ID:          "Storage Legacy Bucket Writer",
							Name:        "Storage Legacy Bucket Writer",
							Description: "Read access to buckets with object listing/creation/deletion",
							Permissions: []interface{}{"roles/storage.legacyBucketWriter"},
						},
					},
				},
			},
		}
		g := domain.Grant{
			Role: "Storage Legacy Bucket Writer",
			Resource: &domain.Resource{
				URN:          "test-bucket-name",
				Name:         "test-bucket-name",
				ProviderType: "gcs",
				ProviderURN:  "test-resource-name",
				Type:         "bucket",
			},
			ID:          "999",
			ResourceID:  "999",
			AccountType: expectedAccountType,
			AccountID:   expectedAccountID,
			Permissions: []string{"Storage Legacy Bucket Writer"},
		}

		actualError := p.GrantAccess(pc, g)

		assert.Error(t, actualError)
	})

	t.Run("should grant the access to bucket resource and return nil error", func(t *testing.T) {
		expectedAccountType := "user"
		expectedAccountID := "test@email.com"

		client := new(mocks.GCSClient)
		p := gcs.NewProvider("gcs")
		p.Clients = map[string]gcs.GCSClient{
			"test-resource-name": client,
		}
		providerURN := "test-resource-name"

		client.On("GrantBucketAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		pc := &domain.ProviderConfig{
			Type: domain.ProviderTypeGCS,
			URN:  providerURN,
			Credentials: gcs.Credentials{
				ServiceAccountKey: base64.StdEncoding.EncodeToString([]byte("service_account-key-json")),
				ResourceName:      "projects/test-resource-name",
			},
			Resources: []*domain.ResourceConfig{
				{
					Type: gcs.ResourceTypeBucket,
					Roles: []*domain.Role{
						{
							ID:          "Storage Legacy Bucket Writer",
							Name:        "Storage Legacy Bucket Writer",
							Description: "Read access to buckets with object listing/creation/deletion",
							Permissions: []interface{}{"roles/storage.legacyBucketWriter"},
						},
					},
				},
			},
		}

		g := domain.Grant{
			Role: "Storage Legacy Bucket Writer",
			Resource: &domain.Resource{
				URN:          "test-bucket-name",
				Name:         "test-bucket-name",
				ProviderType: "gcs",
				ProviderURN:  "test-resource-name",
				Type:         "bucket",
			},
			ID:          "999",
			ResourceID:  "999",
			AccountType: expectedAccountType,
			AccountID:   expectedAccountID,
			Permissions: []string{"Storage Legacy Bucket Writer"},
		}

		actualError := p.GrantAccess(pc, g)
		assert.Nil(t, actualError)
		client.AssertExpectations(t)
	})
}

func TestRevokeAccess(t *testing.T) {
	t.Run("should return error if Provider Config or Appeal doesn't have required parameters", func(t *testing.T) {
		testCases := []struct {
			name           string
			providerConfig *domain.ProviderConfig
			grant          domain.Grant
			expectedError  error
		}{
			{
				name:           "nil provider config",
				providerConfig: nil,
				expectedError:  fmt.Errorf("invalid provider/appeal config: %w", gcs.ErrNilProviderConfig),
			},
			{
				name: "nil resource config",
				providerConfig: &domain.ProviderConfig{
					Type:                domain.ProviderTypeGCS,
					URN:                 "test-URN",
					AllowedAccountTypes: []string{"user", "serviceAccount"},
				},
				grant: domain.Grant{
					ID:          "test-appeal-id",
					AccountType: "user",
				},
				expectedError: fmt.Errorf("invalid provider/appeal config: %w", gcs.ErrNilResource),
			},
			{
				name: "provider type doesnt match",
				providerConfig: &domain.ProviderConfig{
					Type:                domain.ProviderTypeGCS,
					URN:                 "test-URN-1",
					AllowedAccountTypes: []string{"user", "serviceAccount"},
				},
				grant: domain.Grant{
					ID:          "test-appeal-id",
					AccountType: "user",
					Resource: &domain.Resource{
						ID:           "test-resource-id",
						ProviderType: "not-gcs",
					},
				},
				expectedError: fmt.Errorf("invalid provider/appeal config: %w", gcs.ErrProviderTypeMismatch),
			},
			{
				name: "provider urn doesnt match",
				providerConfig: &domain.ProviderConfig{
					Type:                domain.ProviderTypeGCS,
					URN:                 "test-URN-1",
					AllowedAccountTypes: []string{"user", "serviceAccount"},
				},
				grant: domain.Grant{
					ID:          "test-appeal-id",
					AccountType: "user",
					Resource: &domain.Resource{
						ID:           "test-resource-id",
						ProviderType: domain.ProviderTypeGCS,
						ProviderURN:  "not-test-URN-1",
					},
				},
				expectedError: fmt.Errorf("invalid provider/appeal config: %w", gcs.ErrProviderURNMismatch),
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				p := initProvider()
				pc := tc.providerConfig
				a := tc.grant

				actualError := p.RevokeAccess(pc, a)
				assert.EqualError(t, actualError, tc.expectedError.Error())
			})
		}
	})

	t.Run("should return error if error in decoding credentials", func(t *testing.T) {
		p := initProvider()

		pc := &domain.ProviderConfig{
			Credentials: "invalid-credentials-struct",
			Resources: []*domain.ResourceConfig{
				{
					Type: "test-type",
					Roles: []*domain.Role{
						{
							ID:          "test-role",
							Permissions: []interface{}{"test-permission-config"},
						},
					},
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
		assert.Error(t, actualError)
	})

	t.Run("should return error if error in getting the gcs client", func(t *testing.T) {
		expectedAccountType := "user"
		expectedAccountID := "test@email.com"
		p := gcs.NewProvider("gcs")
		providerURN := "test-resource-name"

		pc := &domain.ProviderConfig{
			Type: domain.ProviderTypeGCS,
			URN:  providerURN,
			Credentials: gcs.Credentials{
				ServiceAccountKey: base64.StdEncoding.EncodeToString([]byte("service_account-key-json")),
				ResourceName:      "projects/test-resource-name",
			},
			Resources: []*domain.ResourceConfig{
				{
					Type: gcs.ResourceTypeBucket,
					Roles: []*domain.Role{
						{
							ID:          "Storage Legacy Bucket Writer",
							Name:        "Storage Legacy Bucket Writer",
							Description: "Read access to buckets with object listing/creation/deletion",
							Permissions: []interface{}{"roles/storage.legacyBucketWriter"},
						},
					},
				},
			},
		}
		a := domain.Grant{
			Role: "Storage Legacy Bucket Writer",
			Resource: &domain.Resource{
				URN:          "test-bucket-name",
				Name:         "test-bucket-name",
				ProviderType: "gcs",
				ProviderURN:  "test-resource-name",
				Type:         "bucket",
			},
			ID:          "999",
			ResourceID:  "999",
			AccountType: expectedAccountType,
			AccountID:   expectedAccountID,
			Permissions: []string{"Storage Legacy Bucket Writer"},
		}

		actualError := p.RevokeAccess(pc, a)

		assert.Error(t, actualError)
	})

	t.Run("should revoke the access to bucket resource and return nil error", func(t *testing.T) {
		expectedAccountType := "user"
		expectedAccountID := "test@email.com"

		client := new(mocks.GCSClient)
		p := gcs.NewProvider("gcs")
		p.Clients = map[string]gcs.GCSClient{
			"test-resource-name": client,
		}
		providerURN := "test-resource-name"

		client.On("RevokeBucketAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		pc := &domain.ProviderConfig{
			Type: domain.ProviderTypeGCS,
			URN:  providerURN,
			Credentials: gcs.Credentials{
				ServiceAccountKey: base64.StdEncoding.EncodeToString([]byte("service_account-key-json")),
				ResourceName:      "projects/test-resource-name",
			},
			Resources: []*domain.ResourceConfig{
				{
					Type: gcs.ResourceTypeBucket,
					Roles: []*domain.Role{
						{
							ID:          "Storage Legacy Bucket Writer",
							Name:        "Storage Legacy Bucket Writer",
							Description: "Read access to buckets with object listing/creation/deletion",
							Permissions: []interface{}{"roles/storage.legacyBucketWriter"},
						},
					},
				},
			},
		}

		a := domain.Grant{
			Role: "Storage Legacy Bucket Writer",
			Resource: &domain.Resource{
				URN:          "test-bucket-name",
				Name:         "test-bucket-name",
				ProviderType: "gcs",
				ProviderURN:  "test-resource-name",
				Type:         "bucket",
			},
			ID:          "999",
			ResourceID:  "999",
			AccountType: expectedAccountType,
			AccountID:   expectedAccountID,
			Permissions: []string{"Storage Legacy Bucket Writer"},
		}

		actualError := p.RevokeAccess(pc, a)
		assert.Nil(t, actualError)
		client.AssertExpectations(t)
	})
}

func TestGetRoles(t *testing.T) {
	t.Run("test", func(t *testing.T) {
		p := initProvider()
		providerURN := "test-URN"
		pc := &domain.ProviderConfig{
			URN:         providerURN,
			Credentials: "valid-Credentials",
			Resources:   []*domain.ResourceConfig{{}},
		}
		expectedRoles := []*domain.Role(nil)

		actualRoles, _ := p.GetRoles(pc, gcs.ResourceTypeBucket)

		assert.Equal(t, expectedRoles, actualRoles)
	})
}

func TestGetAccountType(t *testing.T) {
	t.Run("test", func(t *testing.T) {
		p := initProvider()
		expectedAccountTypes := []string{"user", "serviceAccount", "group", "domain"}

		actualAccountypes := p.GetAccountTypes()

		assert.Equal(t, expectedAccountTypes, actualAccountypes)
	})
}

func TestListAccess(t *testing.T) {
	client := new(mocks.GCSClient)
	p := gcs.NewProvider("gcs")
	providerURN := "test-resource-name"
	p.Clients = map[string]gcs.GCSClient{
		providerURN: client,
	}

	dummyProviderConfig := &domain.ProviderConfig{
		Type: domain.ProviderTypeGCS,
		URN:  providerURN,
		Credentials: gcs.Credentials{
			ServiceAccountKey: "service_account-key-json",
			ResourceName:      "projects/test-resource-name",
		},
		Resources: []*domain.ResourceConfig{
			{
				Type: gcs.ResourceTypeBucket,
				Roles: []*domain.Role{
					{
						ID:          "Storage Legacy Bucket Writer",
						Name:        "Storage Legacy Bucket Writer",
						Description: "Read access to buckets with object listing/creation/deletion",
						Permissions: []interface{}{"roles/storage.legacyBucketWriter"},
					},
				},
			},
		},
	}

	dummyResources := []*domain.Resource{}
	expectedResourcesAccess := domain.MapResourceAccess{}
	client.EXPECT().
		ListAccess(mock.AnythingOfType("*context.emptyCtx"), dummyResources).
		Return(expectedResourcesAccess, nil).Once()

	actualResourcesAccess, err := p.ListAccess(context.Background(), *dummyProviderConfig, dummyResources)

	assert.Nil(t, err)
	assert.Equal(t, expectedResourcesAccess, actualResourcesAccess)
	client.AssertExpectations(t)
}

func initProvider() *gcs.Provider {
	return gcs.NewProvider("gcs")
}
