package googlegroup_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/plugins/providers/googlegroup"
	"github.com/goto/guardian/plugins/providers/googlegroup/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	admin "google.golang.org/api/admin/directory/v1"
)

const resourceType = "group"

var memberRole = &domain.Role{
	ID:          "member",
	Name:        "Member",
	Permissions: []interface{}{"MEMBER"},
}

var managerRole = &domain.Role{
	ID:          "manager",
	Name:        "Manager",
	Permissions: []interface{}{"MANAGER"},
}

var ownerRole = &domain.Role{
	ID:          "owner",
	Name:        "Owner",
	Permissions: []interface{}{"OWNER"},
}

var base64EncodedKey = base64.StdEncoding.EncodeToString([]byte("valid_service_account_key"))

func TestGetType(t *testing.T) {
	t.Run("should return the set type in provider", func(t *testing.T) {
		provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, nil, nil)
		actualProviderType := provider.GetType()
		assert.Equal(t, domain.ProviderTypeGoogleGroup, actualProviderType)
	})
}

func TestGetAccountTypes(t *testing.T) {
	t.Run("should return the expected account types", func(t *testing.T) {
		allowedAccountTypes := []string{"user", "google-group", "service-account"}
		provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, nil, nil)
		assert.Equal(t, allowedAccountTypes, provider.GetAccountTypes())
	})
}

func TestGetRoles(t *testing.T) {
	var resourceConfig = &domain.ResourceConfig{
		Type: resourceType,
		Roles: []*domain.Role{
			memberRole,
			managerRole,
			ownerRole,
		},
	}

	var providerConfig = domain.ProviderConfig{
		Type: domain.ProviderTypeGoogleGroup,
		URN:  "test-google-group-provider",
		Credentials: map[string]any{
			"service_account_key_base64": base64EncodedKey,
			"impersonate_user_email":     "test@gojek.com",
		},
		Resources: []*domain.ResourceConfig{resourceConfig},
	}
	t.Run("should return the expected roles", func(t *testing.T) {
		provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, nil, nil)
		actualRoles, err := provider.GetRoles(&providerConfig, resourceType)
		assert.NoError(t, err)
		assert.Equal(t, resourceConfig.Roles, actualRoles)
	})
}

func TestCreateConfig(t *testing.T) {
	var resourceConfig = &domain.ResourceConfig{
		Type: resourceType,
		Roles: []*domain.Role{
			memberRole,
			managerRole,
			ownerRole,
		},
		Filter: "$urn in test-group-1@gojek.com",
	}
	t.Run("should not create config", func(t *testing.T) {
		t.Run("should not create config when credentials are not present", func(t *testing.T) {
			var encryptor = new(mocks.Encryptor)
			var logger = log.NewNoop()
			provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
			err := provider.CreateConfig(&domain.ProviderConfig{
				Type: domain.ProviderTypeGoogleGroup,
			})
			assert.Error(t, err)
			assert.Equal(t, "config validation failed: credentials is required", err.Error())
		})

		t.Run("should not create config when service account key is missing", func(t *testing.T) {
			var encryptor = new(mocks.Encryptor)
			var logger = log.NewNoop()
			provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
			err := provider.CreateConfig(&domain.ProviderConfig{
				Type: domain.ProviderTypeGoogleGroup,
				Credentials: map[string]interface{}{
					"invalid": "credentials",
				},
			})
			assert.Error(t, err)
			assert.Equal(t, "config validation failed: invalid credentials: service_account_key_base64 is required", err.Error())
		})

		t.Run("should not create config when impersonate user email is missing", func(t *testing.T) {
			var encryptor = new(mocks.Encryptor)
			var logger = log.NewNoop()
			provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
			err := provider.CreateConfig(&domain.ProviderConfig{
				Type: domain.ProviderTypeGoogleGroup,
				Credentials: map[string]interface{}{
					"service_account_key_base64": "valid_base64_encoded_string",
				},
			})
			assert.Error(t, err)
			assert.Equal(t, "config validation failed: invalid credentials: impersonate_user_email is required", err.Error())
		})

		t.Run("should not create config when service account key is not base64 encoded", func(t *testing.T) {
			var encryptor = new(mocks.Encryptor)
			var logger = log.NewNoop()
			provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
			err := provider.CreateConfig(&domain.ProviderConfig{
				Type: domain.ProviderTypeGoogleGroup,
				Credentials: map[string]interface{}{
					"service_account_key_base64": "invalid_base64_string",
					"impersonate_user_email":     "test@gojek.com",
				},
			})
			assert.Error(t, err)
			assert.ErrorContains(t, err, "service_account_key_base64 must be a valid base64 encoded string")
		})

		t.Run("should not create config when impersonate user email is invalid", func(t *testing.T) {
			var encryptor = new(mocks.Encryptor)
			var logger = log.NewNoop()
			provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
			err := provider.CreateConfig(&domain.ProviderConfig{
				Type: domain.ProviderTypeGoogleGroup,
				Credentials: map[string]interface{}{
					"service_account_key_base64": base64EncodedKey,
					"impersonate_user_email":     "invalid_email_format",
				},
			})
			assert.Error(t, err)
			assert.Equal(t, "config validation failed: invalid credentials: impersonate_user_email must be a valid email address", err.Error())
		})

		t.Run("should not create config when resource type is invalid", func(t *testing.T) {
			var encryptor = new(mocks.Encryptor)
			var logger = log.NewNoop()
			invalidResourceConfig := &domain.ResourceConfig{
				Type: "invalid_resource_type",
				Roles: []*domain.Role{
					{
						ID:          "invalid_role",
						Name:        "InvalidRole",
						Permissions: []interface{}{"INVALID_PERMISSION"},
					},
				},
			}

			provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
			err := provider.CreateConfig(&domain.ProviderConfig{
				Type: domain.ProviderTypeGoogleGroup,
				Credentials: map[string]interface{}{
					"service_account_key_base64": base64EncodedKey,
					"impersonate_user_email":     "test@gojek.com",
				},
				Resources: []*domain.ResourceConfig{invalidResourceConfig},
			})

			assert.Error(t, err)
			assert.Equal(t, "config validation failed: invalid resource type: invalid_resource_type, group is the only valid type", err.Error())
		})

		t.Run("should not create config when resource permission type is invalid", func(t *testing.T) {
			var encryptor = new(mocks.Encryptor)
			var logger = log.NewNoop()
			invalidResourceConfig := &domain.ResourceConfig{
				Type: resourceType,
				Roles: []*domain.Role{
					{
						ID:          "invalid_role",
						Name:        "InvalidRole",
						Permissions: []interface{}{[]int{1, 2, 3}},
					},
				},
			}

			provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
			err := provider.CreateConfig(&domain.ProviderConfig{
				Type: domain.ProviderTypeGoogleGroup,
				Credentials: map[string]interface{}{
					"service_account_key_base64": base64EncodedKey,
					"impersonate_user_email":     "test@gojek.com",
				},
				Resources: []*domain.ResourceConfig{invalidResourceConfig},
			})

			assert.Error(t, err)
			assert.Equal(t, "config validation failed: unexpected permission type: []int, expected: string", err.Error())
		})

		t.Run("should not create config when resource permission is invalid", func(t *testing.T) {
			var encryptor = new(mocks.Encryptor)
			var logger = log.NewNoop()

			invalidResourceConfig := &domain.ResourceConfig{
				Type: resourceType,
				Roles: []*domain.Role{
					{
						ID:          "invalid_role",
						Name:        "InvalidRole",
						Permissions: []interface{}{"INVALID_PERMISSION"},
					},
				},
			}

			provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
			err := provider.CreateConfig(&domain.ProviderConfig{
				Type: domain.ProviderTypeGoogleGroup,
				Credentials: map[string]interface{}{
					"service_account_key_base64": base64EncodedKey,
					"impersonate_user_email":     "test@gojek.com",
				},
				Resources: []*domain.ResourceConfig{invalidResourceConfig},
			})

			assert.Error(t, err)
			assert.Equal(t, "config validation failed: invalid permission: INVALID_PERMISSION for resource type: group", err.Error())
		})

		t.Run("failed to encrypt credentials", func(t *testing.T) {
			var encryptor = new(mocks.Encryptor)
			var logger = log.NewNoop()

			provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)

			encryptor.On("Encrypt", base64EncodedKey).Once().Return("", assert.AnError)

			err := provider.CreateConfig(&domain.ProviderConfig{
				Type: domain.ProviderTypeGoogleGroup,
				Credentials: map[string]interface{}{
					"service_account_key_base64": base64EncodedKey,
					"impersonate_user_email":     "test@gojek.com",
				},
				Resources: []*domain.ResourceConfig{resourceConfig},
			})

			assert.Error(t, err)
			assert.ErrorContains(t, err, "failed to encrypt service account key:")
			encryptor.AssertExpectations(t)
		})
	})
	t.Run("should create config successfully", func(t *testing.T) {
		var encryptor = new(mocks.Encryptor)
		var logger = log.NewNoop()

		provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)

		encryptor.On("Encrypt", base64EncodedKey).Once().Return("", nil)

		err := provider.CreateConfig(&domain.ProviderConfig{
			Type: domain.ProviderTypeGoogleGroup,
			Credentials: map[string]interface{}{
				"service_account_key_base64": base64EncodedKey,
				"impersonate_user_email":     "test@gojek.com",
			},
			Resources: []*domain.ResourceConfig{resourceConfig},
		})

		assert.NoError(t, err)
		encryptor.AssertExpectations(t)
	})
}

func TestGetResources(t *testing.T) {
	ctx := context.Background()
	var resourceConfig = &domain.ResourceConfig{
		Type: resourceType,
		Roles: []*domain.Role{
			memberRole,
			managerRole,
			ownerRole,
		},
		Filter: "$urn in ['test-group-1@gojek.com']",
	}

	var providerConfig = domain.ProviderConfig{
		Type: domain.ProviderTypeGoogleGroup,
		URN:  "test-google-group-provider",
		Credentials: map[string]any{
			"service_account_key_base64": base64EncodedKey,
			"impersonate_user_email":     "test@gojek.com",
		},
		Resources: []*domain.ResourceConfig{resourceConfig},
	}

	t.Run("should return error on decrypting creds", func(t *testing.T) {
		var encryptor = new(mocks.Encryptor)
		var logger = log.NewNoop()

		provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)

		encryptor.EXPECT().Decrypt(mock.Anything).Return("", assert.AnError)
		defer encryptor.AssertExpectations(t)

		_, err := provider.GetAdminServiceClient(context.Background(), providerConfig)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "unable to decrypt credentials")
	})

	t.Run("should return error on invalid service account key", func(t *testing.T) {
		var encryptor = new(mocks.Encryptor)
		var logger = log.NewNoop()

		provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)

		encryptor.EXPECT().Decrypt(mock.Anything).Return("000", nil)
		defer encryptor.AssertExpectations(t)

		_, err := provider.GetAdminServiceClient(context.Background(), providerConfig)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "failed to decode service account base64 string")
	})

	t.Run("should not return resources if no groups are present", func(t *testing.T) {
		var encryptor = new(mocks.Encryptor)
		var adminProvider = new(mocks.AdminService)
		var logger = log.NewNoop()

		provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
		provider.Clients = map[string]googlegroup.AdminService{
			providerConfig.URN: adminProvider,
		}

		adminProvider.On("ListGroups",
			mock.Anything,
			"my_customer",
			"",
		).Return(nil, "", nil).Once()
		defer adminProvider.AssertExpectations(t)

		resources, err := provider.GetResources(ctx, &providerConfig)
		assert.NoError(t, err)
		assert.Empty(t, resources)
	})

	t.Run("should not return resources if filter is invalid", func(t *testing.T) {
		var encryptor = new(mocks.Encryptor)
		var adminProvider = new(mocks.AdminService)
		var logger = log.NewNoop()

		providerConfigWithInvalidFilter := domain.ProviderConfig{
			Type: domain.ProviderTypeGoogleGroup,
			URN:  "test-google-group-provider",
			Credentials: map[string]any{
				"service_account_key_base64": base64EncodedKey,
				"impersonate_user_email":     "test@gojek.com",
			},
			Resources: []*domain.ResourceConfig{
				{
					Type: resourceType,
					Roles: []*domain.Role{
						memberRole,
						managerRole,
						ownerRole,
					},
					Filter: "$invalid filter",
				},
			},
		}

		provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
		provider.Clients = map[string]googlegroup.AdminService{
			providerConfigWithInvalidFilter.URN: adminProvider,
		}

		mockResp := &admin.Groups{
			Groups: []*admin.Group{
				{
					Id:    "group1",
					Name:  "Test Group 2",
					Email: "test-group-2@gojek.com",
				},
			},
			NextPageToken: "",
		}

		adminProvider.On("ListGroups",
			mock.Anything,
			"my_customer",
			"",
		).Return(mockResp.Groups, mockResp.NextPageToken, nil).Once()
		defer adminProvider.AssertExpectations(t)

		resources, err := provider.GetResources(ctx, &providerConfigWithInvalidFilter)
		assert.NoError(t, err)
		assert.Empty(t, resources)
	})

	t.Run("should not return resources if filter doesn't match", func(t *testing.T) {
		var encryptor = new(mocks.Encryptor)
		var adminProvider = new(mocks.AdminService)
		var logger = log.NewNoop()

		provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
		provider.Clients = map[string]googlegroup.AdminService{
			providerConfig.URN: adminProvider,
		}

		mockResp := &admin.Groups{
			Groups: []*admin.Group{
				{
					Id:    "group1",
					Name:  "Test Group 2",
					Email: "test-group-2@gojek.com",
				},
			},
			NextPageToken: "",
		}

		adminProvider.On("ListGroups",
			mock.Anything,
			"my_customer",
			"",
		).Return(mockResp.Groups, mockResp.NextPageToken, nil).Once()
		defer adminProvider.AssertExpectations(t)

		resources, err := provider.GetResources(ctx, &providerConfig)
		assert.NoError(t, err)
		assert.Empty(t, resources)
	})

	t.Run("should return resources", func(t *testing.T) {
		var encryptor = new(mocks.Encryptor)
		var adminProvider = new(mocks.AdminService)
		var logger = log.NewNoop()

		provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
		provider.Clients = map[string]googlegroup.AdminService{
			providerConfig.URN: adminProvider,
		}

		mockResp := &admin.Groups{
			Groups: []*admin.Group{
				{
					Id:    "group1",
					Name:  "Test Group 1",
					Email: "test-group-1@gojek.com",
				},
			},
			NextPageToken: "",
		}

		adminProvider.On("ListGroups",
			mock.Anything,
			"my_customer",
			"",
		).Return(mockResp.Groups, mockResp.NextPageToken, nil).Once()
		defer adminProvider.AssertExpectations(t)

		resources, err := provider.GetResources(ctx, &providerConfig)
		assert.NoError(t, err)
		assert.Len(t, resources, 1)
		assert.Equal(t, resources[0].URN, mockResp.Groups[0].Email)
	})
}

func TestGrantAccess(t *testing.T) {
	ctx := context.Background()
	var resourceConfig = &domain.ResourceConfig{
		Type: resourceType,
		Roles: []*domain.Role{
			memberRole,
			managerRole,
			ownerRole,
		},
		Filter: "$urn in ['test-group-1@gojek.com']",
	}

	var providerConfig = domain.ProviderConfig{
		Type: domain.ProviderTypeGoogleGroup,
		URN:  "test-google-group-provider",
		Credentials: map[string]any{
			"service_account_key_base64": base64EncodedKey,
			"impersonate_user_email":     "test@gojek.com",
		},
		Resources: []*domain.ResourceConfig{resourceConfig},
	}

	t.Run("should return error on invalid email format", func(t *testing.T) {
		var grant = domain.Grant{
			ID:          "test-appeal-id",
			AccountType: "user",
			AccountID:   "invalid_email_format",
		}
		provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, nil, nil)

		err := provider.GrantAccess(ctx, &providerConfig, grant)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "invalid email format")
	})

	t.Run("should return error for incompatible email format for user/sub-group account type", func(t *testing.T) {
		var grant = domain.Grant{
			ID:          "test-appeal-id",
			AccountType: "user",
			AccountID:   "test@test.iam.gserviceaccount.com",
		}
		provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, nil, nil)

		err := provider.GrantAccess(ctx, &providerConfig, grant)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "invalid email format for user account type")
	})

	t.Run("should return error for incompatible email format for sa account type", func(t *testing.T) {
		var grant = domain.Grant{
			ID:          "test-appeal-id",
			AccountType: "service-account",
			AccountID:   "test@gojek.com",
		}
		provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, nil, nil)

		err := provider.GrantAccess(ctx, &providerConfig, grant)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "invalid email format for service account")
	})

	t.Run("should return error if permissions are invalid", func(t *testing.T) {
		t.Run("should return error if more than 1 permission is specified ", func(t *testing.T) {
			var encryptor = new(mocks.Encryptor)
			var adminProvider = new(mocks.AdminService)
			var logger = log.NewNoop()

			provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
			provider.Clients = map[string]googlegroup.AdminService{
				providerConfig.URN: adminProvider,
			}
			var grant = domain.Grant{
				ID:          "test-appeal-id",
				AccountType: "service-account",
				AccountID:   "test@test.iam.gserviceaccount.com",
				Permissions: []string{"MEMBER", "MANAGER"},
				Resource: &domain.Resource{
					Type: resourceType,
					URN:  "test-group-1@gojek.com",
				},
			}
			err := provider.GrantAccess(ctx, &providerConfig, grant)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "unexpected number of permissions")
		})

		t.Run("should return error if permission is invalid ", func(t *testing.T) {
			var encryptor = new(mocks.Encryptor)
			var adminProvider = new(mocks.AdminService)
			var logger = log.NewNoop()

			provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
			provider.Clients = map[string]googlegroup.AdminService{
				providerConfig.URN: adminProvider,
			}
			var grant = domain.Grant{
				ID:          "test-appeal-id",
				AccountType: "service-account",
				AccountID:   "test@test.iam.gserviceaccount.com",
				Permissions: []string{"INVALID_PERMISSION"},
				Resource: &domain.Resource{
					Type: resourceType,
					URN:  "test-group-1@gojek.com",
				},
			}
			err := provider.GrantAccess(ctx, &providerConfig, grant)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "invalid grant permission")
		})
	})

	t.Run("should return error when resource type is invalid", func(t *testing.T) {
		var encryptor = new(mocks.Encryptor)
		var adminProvider = new(mocks.AdminService)
		var logger = log.NewNoop()

		provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
		provider.Clients = map[string]googlegroup.AdminService{
			providerConfig.URN: adminProvider,
		}
		var grant = domain.Grant{
			ID:          "test-appeal-id",
			AccountType: "service-account",
			AccountID:   "test@test.iam.gserviceaccount.com",
			Permissions: []string{"MEMBER"},
			Resource: &domain.Resource{
				Type: "invalid_resource_type",
				URN:  "test-group-1@gojek.com",
			},
		}
		err := provider.GrantAccess(ctx, &providerConfig, grant)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "invalid resource type")
	})

	t.Run("should return error if client returned error", func(t *testing.T) {
		var encryptor = new(mocks.Encryptor)
		var adminProvider = new(mocks.AdminService)
		var logger = log.NewNoop()

		provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
		provider.Clients = map[string]googlegroup.AdminService{
			providerConfig.URN: adminProvider,
		}
		var grant = domain.Grant{
			ID:          "test-appeal-id",
			AccountType: "service-account",
			AccountID:   "test@test.iam.gserviceaccount.com",
			Permissions: []string{"MEMBER"},
			Resource: &domain.Resource{
				Type: resourceType,
				URN:  "test-group-1@gojek.com",
			},
		}

		adminProvider.On("InsertMember",
			mock.Anything,
			grant.Resource.URN,
			mock.MatchedBy(func(member *admin.Member) bool {
				return member.Email == grant.AccountID && member.Role == "MEMBER"
			})).Return(nil, assert.AnError).Once()
		defer adminProvider.AssertExpectations(t)

		err := provider.GrantAccess(ctx, &providerConfig, grant)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "failed to add member")
	})

	t.Run("should not return error if member already exists", func(t *testing.T) {
		var encryptor = new(mocks.Encryptor)
		var adminProvider = new(mocks.AdminService)
		var logger = log.NewNoop()

		provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
		provider.Clients = map[string]googlegroup.AdminService{
			providerConfig.URN: adminProvider,
		}
		var grant = domain.Grant{
			ID:          "test-appeal-id",
			AccountType: "service-account",
			AccountID:   "test@test.iam.gserviceaccount.com",
			Permissions: []string{"MEMBER"},
			Resource: &domain.Resource{
				Type: resourceType,
				URN:  "test-group-1@gojek.com",
			},
		}

		adminProvider.On("InsertMember",
			mock.Anything,
			grant.Resource.URN,
			mock.MatchedBy(func(member *admin.Member) bool {
				return member.Email == grant.AccountID && member.Role == "MEMBER"
			})).Return(nil, errors.New("Member already exists")).Once()
		defer adminProvider.AssertExpectations(t)

		err := provider.GrantAccess(ctx, &providerConfig, grant)
		assert.NoError(t, err)
	})

	t.Run("should grant access successfully", func(t *testing.T) {
		var encryptor = new(mocks.Encryptor)
		var adminProvider = new(mocks.AdminService)
		var logger = log.NewNoop()

		provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
		provider.Clients = map[string]googlegroup.AdminService{
			providerConfig.URN: adminProvider,
		}
		var grant = domain.Grant{
			ID:          "test-appeal-id",
			AccountType: "service-account",
			AccountID:   "test@test.iam.gserviceaccount.com",
			Permissions: []string{"MEMBER"},
			Resource: &domain.Resource{
				Type: resourceType,
				URN:  "test-group-1@gojek.com",
			},
		}

		adminProvider.On("InsertMember",
			mock.Anything,
			grant.Resource.URN,
			mock.MatchedBy(func(member *admin.Member) bool {
				return member.Email == grant.AccountID && member.Role == "MEMBER"
			})).Return(&admin.Member{Email: "test@test.iam.gserviceaccount.com"}, nil).Once()
		defer adminProvider.AssertExpectations(t)

		err := provider.GrantAccess(ctx, &providerConfig, grant)
		assert.NoError(t, err)
	})
}

func TestRevokeAccess(t *testing.T) {
	ctx := context.Background()
	var resourceConfig = &domain.ResourceConfig{
		Type: resourceType,
		Roles: []*domain.Role{
			memberRole,
			managerRole,
			ownerRole,
		},
		Filter: "$urn in ['test-group-1@gojek.com']",
	}

	var providerConfig = domain.ProviderConfig{
		Type: domain.ProviderTypeGoogleGroup,
		URN:  "test-google-group-provider",
		Credentials: map[string]any{
			"service_account_key_base64": base64EncodedKey,
			"impersonate_user_email":     "test@gojek.com",
		},
		Resources: []*domain.ResourceConfig{resourceConfig},
	}

	t.Run("should return error if permissions are invalid", func(t *testing.T) {
		t.Run("should return error if more than 1 permission is specified ", func(t *testing.T) {
			var encryptor = new(mocks.Encryptor)
			var adminProvider = new(mocks.AdminService)
			var logger = log.NewNoop()

			provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
			provider.Clients = map[string]googlegroup.AdminService{
				providerConfig.URN: adminProvider,
			}
			var grant = domain.Grant{
				ID:          "test-appeal-id",
				AccountType: "service-account",
				AccountID:   "test@test.iam.gserviceaccount.com",
				Permissions: []string{"MEMBER", "MANAGER"},
				Resource: &domain.Resource{
					Type: resourceType,
					URN:  "test-group-1@gojek.com",
				},
			}
			err := provider.RevokeAccess(ctx, &providerConfig, grant)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "unexpected number of permissions")
		})

		t.Run("should return error if permission is invalid ", func(t *testing.T) {
			var encryptor = new(mocks.Encryptor)
			var adminProvider = new(mocks.AdminService)
			var logger = log.NewNoop()

			provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
			provider.Clients = map[string]googlegroup.AdminService{
				providerConfig.URN: adminProvider,
			}
			var grant = domain.Grant{
				ID:          "test-appeal-id",
				AccountType: "service-account",
				AccountID:   "test@test.iam.gserviceaccount.com",
				Permissions: []string{"INVALID_PERMISSION"},
				Resource: &domain.Resource{
					Type: resourceType,
					URN:  "test-group-1@gojek.com",
				},
			}
			err := provider.RevokeAccess(ctx, &providerConfig, grant)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "invalid grant permission")
		})
	})

	t.Run("should return error when resource type is invalid", func(t *testing.T) {
		var encryptor = new(mocks.Encryptor)
		var adminProvider = new(mocks.AdminService)
		var logger = log.NewNoop()

		provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
		provider.Clients = map[string]googlegroup.AdminService{
			providerConfig.URN: adminProvider,
		}
		var grant = domain.Grant{
			ID:          "test-appeal-id",
			AccountType: "service-account",
			AccountID:   "test@test.iam.gserviceaccount.com",
			Permissions: []string{"MEMBER"},
			Resource: &domain.Resource{
				Type: "invalid_resource_type",
				URN:  "test-group-1@gojek.com",
			},
		}
		err := provider.RevokeAccess(ctx, &providerConfig, grant)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "invalid resource type")
	})

	t.Run("should return error if client returned error", func(t *testing.T) {
		var encryptor = new(mocks.Encryptor)
		var adminProvider = new(mocks.AdminService)
		var logger = log.NewNoop()

		provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
		provider.Clients = map[string]googlegroup.AdminService{
			providerConfig.URN: adminProvider,
		}
		var grant = domain.Grant{
			ID:          "test-appeal-id",
			AccountType: "service-account",
			AccountID:   "test@test.iam.gserviceaccount.com",
			Permissions: []string{"MEMBER"},
			Resource: &domain.Resource{
				Type: resourceType,
				URN:  "test-group-1@gojek.com",
			},
		}

		adminProvider.On("RemoveMember",
			mock.Anything,
			grant.Resource.URN,
			grant.AccountID).Return(assert.AnError).Once()
		defer adminProvider.AssertExpectations(t)

		err := provider.RevokeAccess(ctx, &providerConfig, grant)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "failed to remove member")
	})

	t.Run("should not return error if member already exists", func(t *testing.T) {
		var encryptor = new(mocks.Encryptor)
		var adminProvider = new(mocks.AdminService)
		var logger = log.NewNoop()

		provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
		provider.Clients = map[string]googlegroup.AdminService{
			providerConfig.URN: adminProvider,
		}
		var grant = domain.Grant{
			ID:          "test-appeal-id",
			AccountType: "service-account",
			AccountID:   "test@test.iam.gserviceaccount.com",
			Permissions: []string{"MEMBER"},
			Resource: &domain.Resource{
				Type: resourceType,
				URN:  "test-group-1@gojek.com",
			},
		}

		adminProvider.On("RemoveMember",
			mock.Anything,
			grant.Resource.URN,
			grant.AccountID).Return(errors.New("Resource Not Found")).Once()
		defer adminProvider.AssertExpectations(t)

		err := provider.RevokeAccess(ctx, &providerConfig, grant)
		assert.NoError(t, err)
	})

	t.Run("should grant access successfully", func(t *testing.T) {
		var encryptor = new(mocks.Encryptor)
		var adminProvider = new(mocks.AdminService)
		var logger = log.NewNoop()

		provider := googlegroup.NewProvider(domain.ProviderTypeGoogleGroup, encryptor, logger)
		provider.Clients = map[string]googlegroup.AdminService{
			providerConfig.URN: adminProvider,
		}
		var grant = domain.Grant{
			ID:          "test-appeal-id",
			AccountType: "service-account",
			AccountID:   "test@test.iam.gserviceaccount.com",
			Permissions: []string{"MEMBER"},
			Resource: &domain.Resource{
				Type: resourceType,
				URN:  "test-group-1@gojek.com",
			},
		}

		adminProvider.On("RemoveMember",
			mock.Anything,
			grant.Resource.URN,
			grant.AccountID).Return(nil).Once()
		defer adminProvider.AssertExpectations(t)

		err := provider.RevokeAccess(ctx, &providerConfig, grant)
		assert.NoError(t, err)
	})
}
