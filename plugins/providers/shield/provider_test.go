package shield_test

import (
	"context"
	"errors"
	"testing"

	"github.com/goto/guardian/pkg/log"

	"github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/mocks"
	"github.com/goto/guardian/plugins/providers/shield"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGetType(t *testing.T) {
	t.Run("should return provider type name", func(t *testing.T) {
		expectedTypeName := domain.ProviderTypeShield
		logger := log.NewCtxLogger("info", []string{"test"})
		p := shield.NewProvider(expectedTypeName, logger)

		actualTypeName := p.GetType()

		assert.Equal(t, expectedTypeName, actualTypeName)
	})
}

func TestCreateConfig(t *testing.T) {
	t.Run("should return error if there resource config is invalid", func(t *testing.T) {
		providerURN := "test-provider-urn"
		client := new(mocks.ShieldClient)
		logger := log.NewCtxLogger("info", []string{"test"})
		p := shield.NewProvider("", logger)
		p.Clients = map[string]shield.ShieldClient{
			providerURN: client,
		}

		testcases := []struct {
			pc *domain.ProviderConfig
		}{
			{
				pc: &domain.ProviderConfig{
					Credentials: shield.Credentials{
						Host:      "localhost",
						AuthEmail: "test-email",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: "invalid resource type",
						},
					},
				},
			},
			{
				pc: &domain.ProviderConfig{
					Credentials: shield.Credentials{
						Host:      "localhost",
						AuthEmail: "test-email",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: shield.ResourceTypeTeam,
							Roles: []*domain.Role{
								{
									ID:          "member",
									Permissions: []interface{}{"wrong permissions"},
								},
							},
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

	t.Run("should not return error if parse and valid of Credentials are correct", func(t *testing.T) {
		providerURN := "test-provider-urn"
		client := new(mocks.ShieldClient)
		logger := log.NewCtxLogger("info", []string{"test"})
		p := shield.NewProvider("", logger)
		p.Clients = map[string]shield.ShieldClient{
			providerURN: client,
		}

		testcases := []struct {
			pc            *domain.ProviderConfig
			expectedError error
		}{
			{
				pc: &domain.ProviderConfig{
					Credentials: shield.Credentials{
						Host:       "localhost",
						AuthEmail:  "test-email",
						AuthHeader: "X-Auth-Email",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: shield.ResourceTypeTeam,
							Roles: []*domain.Role{
								{
									ID:          "member",
									Permissions: []interface{}{"users"},
								},
								{
									ID:          "admin",
									Permissions: []interface{}{"admins"},
								},
							},
						},
					},
					URN: providerURN,
				},
				expectedError: nil,
			},
			{
				pc: &domain.ProviderConfig{
					Credentials: shield.Credentials{
						Host:       "localhost",
						AuthEmail:  "test-email",
						AuthHeader: "X-Auth-Email",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: shield.ResourceTypeProject,
							Roles: []*domain.Role{
								{
									ID:          "admin",
									Permissions: []interface{}{"admins"},
								},
							},
						},
					},
					URN: providerURN,
				},
				expectedError: nil,
			},
			{
				pc: &domain.ProviderConfig{
					Credentials: shield.Credentials{
						Host:       "localhost",
						AuthEmail:  "test-email",
						AuthHeader: "X-Auth-Email",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: shield.ResourceTypeOrganization,
							Roles: []*domain.Role{
								{
									ID:          "admin",
									Permissions: []interface{}{"admins"},
								},
							},
						},
					},
					URN: providerURN,
				},
				expectedError: nil,
			},
		}

		client.On("GetNamespaces", mock.Anything).Return([]*shield.Namespace{
			{
				ID:   "team",
				Name: "Team",
			},
			{
				ID:   "project",
				Name: "Project",
			},
			{
				ID:   "organization",
				Name: "Organization",
			},
		}, nil)

		for _, tc := range testcases {
			actualError := p.CreateConfig(tc.pc)
			assert.Equal(t, tc.expectedError, actualError)
		}
	})
}

func TestGetResources(t *testing.T) {
	ctx := context.Background()
	t.Run("should return error if credentials is invalid", func(t *testing.T) {
		logger := log.NewCtxLogger("info", []string{"test"})
		p := shield.NewProvider("", logger)

		pc := &domain.ProviderConfig{
			Credentials: "invalid-creds",
		}

		actualResources, actualError := p.GetResources(ctx, pc)

		assert.Nil(t, actualResources)
		assert.Error(t, actualError)
	})

	t.Run("should return error if got any on getting team resources", func(t *testing.T) {
		providerURN := "test-provider-urn"
		client := new(mocks.ShieldClient)
		logger := log.NewCtxLogger("info", []string{"test"})
		p := shield.NewProvider("", logger)
		p.Clients = map[string]shield.ShieldClient{
			providerURN: client,
		}

		pc := &domain.ProviderConfig{
			URN:         providerURN,
			Credentials: map[string]interface{}{},
			Resources: []*domain.ResourceConfig{
				{
					Type: shield.ResourceTypeTeam,
				},
			},
		}
		expectedError := errors.New("client error")
		client.On("GetGroups", mock.Anything).Return(nil, expectedError).Once()

		actualResources, actualError := p.GetResources(context.TODO(), pc)

		assert.Nil(t, actualResources)
		assert.EqualError(t, actualError, expectedError.Error())
	})

	t.Run("should return error if got any on getting project resources", func(t *testing.T) {
		providerURN := "test-provider-urn"
		client := new(mocks.ShieldClient)
		logger := log.NewCtxLogger("info", []string{"test"})
		p := shield.NewProvider("", logger)
		p.Clients = map[string]shield.ShieldClient{
			providerURN: client,
		}

		pc := &domain.ProviderConfig{
			URN:         providerURN,
			Credentials: map[string]interface{}{},
			Resources: []*domain.ResourceConfig{
				{
					Type: shield.ResourceTypeProject,
				},
			},
		}
		expectedError := errors.New("client error")
		client.On("GetProjects", mock.Anything).Return(nil, expectedError).Once()

		actualResources, actualError := p.GetResources(ctx, pc)

		assert.Nil(t, actualResources)
		assert.EqualError(t, actualError, expectedError.Error())
	})

	t.Run("should return error if got any on getting organization resources", func(t *testing.T) {
		providerURN := "test-provider-urn"
		client := new(mocks.ShieldClient)
		logger := log.NewCtxLogger("info", []string{"test"})
		p := shield.NewProvider("", logger)
		p.Clients = map[string]shield.ShieldClient{
			providerURN: client,
		}

		pc := &domain.ProviderConfig{
			URN:         providerURN,
			Credentials: map[string]interface{}{},
			Resources: []*domain.ResourceConfig{
				{
					Type: shield.ResourceTypeOrganization,
				},
			},
		}
		expectedError := errors.New("client error")
		client.On("GetOrganizations", mock.Anything).Return(nil, expectedError).Once()

		actualResources, actualError := p.GetResources(ctx, pc)

		assert.Nil(t, actualResources)
		assert.EqualError(t, actualError, expectedError.Error())
	})

	t.Run("should return error if got any on getting dynamic resources", func(t *testing.T) {
		providerURN := "test-provider-urn"
		client := new(mocks.ShieldClient)
		logger := log.NewCtxLogger("info", []string{"test"})
		p := shield.NewProvider("", logger)
		p.Clients = map[string]shield.ShieldClient{
			providerURN: client,
		}

		pc := &domain.ProviderConfig{
			URN:         providerURN,
			Credentials: map[string]interface{}{},
			Resources: []*domain.ResourceConfig{
				{
					Type: "dynamic_resource_type",
				},
			},
		}
		expectedError := errors.New("client error")
		client.On("GetResources", mock.Anything, "dynamic_resource_type").Return(nil, expectedError).Once()

		actualResources, actualError := p.GetResources(ctx, pc)

		assert.Nil(t, actualResources)
		assert.EqualError(t, actualError, expectedError.Error())
	})

	t.Run("should return list of resources and nil error on success", func(t *testing.T) {
		providerURN := "test-provider-urn"
		client := new(mocks.ShieldClient)
		logger := log.NewCtxLogger("info", []string{"test"})
		p := shield.NewProvider("", logger)
		p.Clients = map[string]shield.ShieldClient{
			providerURN: client,
		}

		pc := &domain.ProviderConfig{
			URN:         providerURN,
			Credentials: map[string]interface{}{},
			Resources: []*domain.ResourceConfig{
				{
					Type: shield.ResourceTypeTeam,
				},
				{
					Type: shield.ResourceTypeProject,
				},
				{
					Type: shield.ResourceTypeOrganization,
				},
				{
					Type: "dynamic_resource_type",
				},
			},
		}
		expectedTeams := []*shield.Group{
			{
				ID:    "team_id",
				Name:  "team_1",
				OrgId: "org_id",
				Metadata: shield.Metadata{
					Email:   "team_1@gojek.com",
					Privacy: "public",
					Slack:   "team_1_slack",
				},
				Admins: []string{"testTeamAdmin@gmail.com"},
			},
		}
		client.On("GetGroups", mock.Anything).Return(expectedTeams, nil).Once()

		expectedProjects := []*shield.Project{
			{
				ID:     "project_id",
				Name:   "project_1",
				OrgId:  "org_id",
				Admins: []string{"testProjectAdmin@gmail.com"},
			},
		}
		client.On("GetProjects", mock.Anything).Return(expectedProjects, nil).Once()

		expectedOrganizations := []*shield.Organization{
			{
				ID:     "org_id",
				Name:   "org_1",
				Admins: []string{"testOrganizationAdmin@gmail.com"},
			},
		}

		client.On("GetOrganizations", mock.Anything).Return(expectedOrganizations, nil).Once()

		expectedDynamicResources := []*shield.Resource{
			{
				ID:   "dynamic_resource_id",
				Name: "dynamic_resource_1",
				URN:  "dynamic_resource:dynamic_resource_1",
				Namespace: shield.Namespace{
					ID:   "dynamic_resource_type",
					Name: "Dynamic Namespace",
				},
			},
		}

		client.On("GetResources", mock.Anything, "dynamic_resource_type").Return(expectedDynamicResources, nil).Once()

		expectedResources := []*domain.Resource{
			{
				Type:        shield.ResourceTypeTeam,
				URN:         "team:team_id",
				ProviderURN: providerURN,
				Name:        "team_1",
				Details: map[string]interface{}{
					"id":     "team_id",
					"orgId":  "org_id",
					"admins": []string{"testTeamAdmin@gmail.com"},
					"metadata": shield.Metadata{
						Email:   "team_1@gojek.com",
						Privacy: "public",
						Slack:   "team_1_slack",
					},
				},
				GlobalURN: "urn:shield:test-provider-urn:team:team_id",
			}, {
				Type:        shield.ResourceTypeProject,
				URN:         "project:project_id",
				ProviderURN: providerURN,
				Name:        "project_1",
				Details: map[string]interface{}{
					"id":     "project_id",
					"orgId":  "org_id",
					"admins": []string{"testProjectAdmin@gmail.com"},
				},
				GlobalURN: "urn:shield:test-provider-urn:project:project_id",
			},
			{
				Type:        shield.ResourceTypeOrganization,
				URN:         "organization:org_id",
				ProviderURN: providerURN,
				Name:        "org_1",
				Details: map[string]interface{}{
					"id":     "org_id",
					"admins": []string{"testOrganizationAdmin@gmail.com"},
				},
				GlobalURN: "urn:shield:test-provider-urn:organization:org_id",
			},
			{
				Type:        "dynamic_resource_type",
				URN:         "resource:dynamic_resource_id",
				ProviderURN: providerURN,
				Name:        "dynamic_resource_1",
				Details: map[string]interface{}{
					"urn": "dynamic_resource:dynamic_resource_1",
					"namespace": shield.Namespace{
						ID:   "dynamic_resource_type",
						Name: "Dynamic Namespace",
					},
				},
				GlobalURN: "urn:shield:test-provider-urn:resource:dynamic_resource_id",
			},
		}

		actualResources, actualError := p.GetResources(ctx, pc)

		assert.Equal(t, expectedResources, actualResources)
		assert.Nil(t, actualError)
	})
}

func TestGrantAccess(t *testing.T) {
	ctx := context.Background()
	mockCtx := mock.MatchedBy(func(ctx context.Context) bool { return true })
	t.Run("should return error if credentials is invalid", func(t *testing.T) {
		logger := log.NewCtxLogger("info", []string{"test"})
		p := shield.NewProvider("", logger)

		pc := &domain.ProviderConfig{
			Credentials: "invalid-credentials",
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

		actualError := p.GrantAccess(ctx, pc, a)
		assert.Error(t, actualError)
	})

	t.Run("given team resource", func(t *testing.T) {
		t.Run("should return error if there is an error in granting team access", func(t *testing.T) {
			providerURN := "test-provider-urn"
			expectedError := errors.New("client error")
			client := new(mocks.ShieldClient)
			logger := log.NewCtxLogger("info", []string{"test"})
			p := shield.NewProvider("", logger)
			p.Clients = map[string]shield.ShieldClient{
				providerURN: client,
			}

			expectedUserEmail := "test@email.com"
			expectedUser := &shield.User{
				ID:    "test_user_id",
				Name:  "test_user",
				Email: expectedUserEmail,
			}

			client.On("GetSelfUser", mock.MatchedBy(func(ctx context.Context) bool { return true }), expectedUserEmail).Return(expectedUser, nil).Once()
			client.On("GrantGroupAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(expectedError).Once()

			pc := &domain.ProviderConfig{
				Credentials: shield.Credentials{
					Host:      "localhost",
					AuthEmail: "test_email",
				},
				Resources: []*domain.ResourceConfig{
					{
						Type: shield.ResourceTypeTeam,
						Roles: []*domain.Role{
							{
								ID:          "test-role",
								Permissions: []interface{}{"test-permission-config"},
							},
						},
					},
				},
				URN: providerURN,
			}
			a := domain.Grant{
				Resource: &domain.Resource{
					Type: shield.ResourceTypeTeam,
					URN:  "team:team_id",
					Name: "team_1",
					Details: map[string]interface{}{
						"id":     "team_id",
						"orgId":  "456",
						"admins": []interface{}{"testAdmin@email.com"},
						"metadata": shield.Metadata{
							Email:   "team_1@gojek.com",
							Privacy: "public",
							Slack:   "team_1_slack",
						},
					},
				},
				Role:        "test-role",
				AccountID:   expectedUserEmail,
				Permissions: []string{"test-permission-config"},
			}

			actualError := p.GrantAccess(ctx, pc, a)

			assert.EqualError(t, actualError, expectedError.Error())
		})

		t.Run("should return nil error if granting access is successful", func(t *testing.T) {
			providerURN := "test-provider-urn"
			logger := log.NewCtxLogger("info", []string{"test"})
			client := new(mocks.ShieldClient)
			expectedTeam := &shield.Group{
				Name: "team_1",
				ID:   "team_id",
			}

			expectedUserEmail := "test@email.com"
			expectedUser := &shield.User{
				ID:    "test_user_id",
				Name:  "test_user",
				Email: expectedUserEmail,
			}

			expectedRole := "users"
			p := shield.NewProvider("", logger)
			p.Clients = map[string]shield.ShieldClient{
				providerURN: client,
			}
			client.On("GetSelfUser", mock.MatchedBy(func(ctx context.Context) bool { return true }), expectedUserEmail).Return(expectedUser, nil).Once()
			client.On("GrantGroupAccess", expectedTeam, expectedUser.ID, expectedRole).Return(nil).Once()

			pc := &domain.ProviderConfig{
				Credentials: shield.Credentials{
					Host:      "localhost",
					AuthEmail: "test_email",
				},
				Resources: []*domain.ResourceConfig{
					{
						Type: shield.ResourceTypeTeam,
						Roles: []*domain.Role{
							{
								ID:          "member",
								Permissions: []interface{}{expectedRole},
							},
						},
					},
				},
				URN: providerURN,
			}
			a := domain.Grant{
				Resource: &domain.Resource{
					Type: shield.ResourceTypeTeam,
					URN:  "team:team_id",
					Name: "team_1",
					Details: map[string]interface{}{
						"id":     "team_id",
						"orgId":  "456",
						"admins": []interface{}{"testAdmin@email.com"},
						"metadata": shield.Metadata{
							Email:   "team_1@gojek.com",
							Privacy: "public",
							Slack:   "team_1_slack",
						},
					},
				},
				Role:       "member",
				AccountID:  expectedUserEmail,
				ResourceID: "999",
				ID:         "999",
			}

			actualError := p.GrantAccess(ctx, pc, a)

			assert.Nil(t, actualError)
		})
	})

	t.Run("given project resource", func(t *testing.T) {
		t.Run("should return error if there is an error in granting project access", func(t *testing.T) {
			providerURN := "test-provider-urn"
			expectedError := errors.New("client error")
			client := new(mocks.ShieldClient)
			logger := log.NewCtxLogger("info", []string{"test"})
			p := shield.NewProvider("", logger)
			p.Clients = map[string]shield.ShieldClient{
				providerURN: client,
			}

			expectedUserEmail := "test@email.com"
			expectedUser := &shield.User{
				ID:    "test_user_id",
				Name:  "test_user",
				Email: expectedUserEmail,
			}

			client.On("GetSelfUser", mockCtx, expectedUserEmail).Return(expectedUser, nil).Once()
			client.On("GrantProjectAccess", mockCtx, mock.Anything, mock.Anything, mock.Anything).Return(expectedError).Once()

			pc := &domain.ProviderConfig{
				Credentials: shield.Credentials{
					Host:      "localhost",
					AuthEmail: "test_email",
				},
				Resources: []*domain.ResourceConfig{
					{
						Type: shield.ResourceTypeProject,
						Roles: []*domain.Role{
							{
								ID:          "test-role",
								Permissions: []interface{}{"test-permission-config"},
							},
						},
					},
				},
				URN: providerURN,
			}
			a := domain.Grant{
				Resource: &domain.Resource{
					Type: shield.ResourceTypeProject,
					URN:  "project:project_id",
					Name: "project_1",
					Details: map[string]interface{}{
						"id":     "project_id",
						"orgId":  "456",
						"admins": []interface{}{"testAdmin@email.com"},
					},
				},
				Role:        "test-role",
				AccountID:   expectedUserEmail,
				Permissions: []string{"test-permission-config"},
			}

			actualError := p.GrantAccess(ctx, pc, a)

			assert.EqualError(t, actualError, expectedError.Error())
		})

		t.Run("should return nil error if granting access is successful", func(t *testing.T) {
			providerURN := "test-provider-urn"
			logger := log.NewCtxLogger("info", []string{"test"})
			client := new(mocks.ShieldClient)
			expectedProject := &shield.Project{
				Name: "project_1",
				ID:   "project_id",
			}
			expectedUserEmail := "test@email.com"
			expectedUser := &shield.User{
				ID:    "test_user_id",
				Name:  "test_user",
				Email: expectedUserEmail,
			}

			expectedRole := "admins"
			p := shield.NewProvider("", logger)
			p.Clients = map[string]shield.ShieldClient{
				providerURN: client,
			}

			client.On("GetSelfUser", mockCtx, expectedUserEmail).Return(expectedUser, nil).Once()
			client.On("GrantProjectAccess", mockCtx, expectedProject, expectedUser.ID, expectedRole).Return(nil).Once()

			pc := &domain.ProviderConfig{
				Credentials: shield.Credentials{
					Host:      "localhost",
					AuthEmail: "test_email",
				},
				Resources: []*domain.ResourceConfig{
					{
						Type: shield.ResourceTypeProject,
						Roles: []*domain.Role{
							{
								ID:          "admin",
								Permissions: []interface{}{expectedRole},
							},
						},
					},
				},
				URN: providerURN,
			}
			a := domain.Grant{
				Resource: &domain.Resource{
					Type: shield.ResourceTypeProject,
					URN:  "project:project_id",
					Name: "project_1",
					Details: map[string]interface{}{
						"id":     "project_id",
						"orgId":  "456",
						"admins": []interface{}{"testAdmin@email.com"},
					},
				},
				Role:       "admin",
				AccountID:  expectedUserEmail,
				ResourceID: "999",
				ID:         "999",
			}

			actualError := p.GrantAccess(ctx, pc, a)

			assert.Nil(t, actualError)
		})
	})
	t.Run("given resource type", func(t *testing.T) {
		providerURN := "test-provider-urn"
		logger := log.NewCtxLogger("info", []string{"test"})
		client := new(mocks.ShieldClient)
		expectedResource := &shield.Resource{
			Name: "test-resource",
			ID:   "test_id",
			Namespace: shield.Namespace{
				Name: "test-namespace",
				ID:   "test_namespace_id",
			},
		}

		expectedUserEmail := "test@email.com"
		expectedUser := &shield.User{
			ID:    "test_user_id",
			Name:  "test_user",
			Email: expectedUserEmail,
		}

		expectedRole := "admins"
		p := shield.NewProvider("", logger)
		p.Clients = map[string]shield.ShieldClient{
			providerURN: client,
		}
		a := domain.Grant{
			Resource: &domain.Resource{
				Type: "test-type",
				Name: "test-resource",
				Details: map[string]interface{}{
					"id": "test_id",
					"namespace": map[string]interface{}{
						"name": "test-namespace",
						"id":   "test_namespace_id",
					},
				},
			},
			Role:       "admin",
			AccountID:  expectedUserEmail,
			ResourceID: "999",
			ID:         "999",
		}

		pc := &domain.ProviderConfig{
			Credentials: shield.Credentials{
				Host:          "localhost",
				AuthEmail:     "test_email",
				ClientVersion: "new",
			},
			Resources: []*domain.ResourceConfig{
				{
					Type: "test-type",
					Roles: []*domain.Role{
						{
							ID:          "admin",
							Permissions: []interface{}{expectedRole},
						},
					},
				},
			},
			URN: providerURN,
		}
		t.Run("should return error if there is an error in granting resource access", func(t *testing.T) {
			expectedError := errors.New("client error")

			client.On("GetSelfUser", mockCtx, expectedUserEmail).Return(expectedUser, nil).Once()
			client.On("GrantResourceAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(expectedError).Once()

			pc := &domain.ProviderConfig{
				Credentials: shield.Credentials{
					Host:      "localhost",
					AuthEmail: "test_email",
				},
				Resources: []*domain.ResourceConfig{
					{
						Type: shield.ResourceTypeTeam,
						Roles: []*domain.Role{
							{
								ID:          "test-role",
								Permissions: []interface{}{"test-permission-config"},
							},
						},
					},
				},
				URN: providerURN,
			}
			a := domain.Grant{
				Resource: &domain.Resource{
					Type:    "-type",
					Name:    "-resource",
					Details: map[string]interface{}{},
				},
				Role:        "test-role",
				AccountID:   expectedUserEmail,
				Permissions: []string{"test-permission-config"},
			}

			actualError := p.GrantAccess(ctx, pc, a)
			assert.EqualError(t, actualError, expectedError.Error())
		})
		t.Run("should return nil error if granting access is successful", func(t *testing.T) {
			client.On("GetSelfUser", mockCtx, expectedUserEmail).Return(expectedUser, nil).Once()
			client.On("GrantResourceAccess", mockCtx, expectedResource, expectedUser.ID, expectedRole).Return(nil).Once()

			actualError := p.GrantAccess(ctx, pc, a)
			assert.Nil(t, actualError)
		})
	})
	t.Run("given organization resource", func(t *testing.T) {
		t.Run("should return error if there is an error in granting organization access", func(t *testing.T) {
			providerURN := "test-provider-urn"
			expectedError := errors.New("client error")
			client := new(mocks.ShieldClient)
			logger := log.NewCtxLogger("info", []string{"test"})
			p := shield.NewProvider("", logger)
			p.Clients = map[string]shield.ShieldClient{
				providerURN: client,
			}

			expectedUserEmail := "test@email.com"
			expectedUser := &shield.User{
				ID:    "test_user_id",
				Name:  "test_user",
				Email: expectedUserEmail,
			}

			client.On("GetSelfUser", mockCtx, expectedUserEmail).Return(expectedUser, nil).Once()
			client.On("GrantOrganizationAccess", mockCtx, mock.Anything, mock.Anything, mock.Anything).Return(expectedError).Once()

			pc := &domain.ProviderConfig{
				Credentials: shield.Credentials{
					Host:      "localhost",
					AuthEmail: "test_email",
				},
				Resources: []*domain.ResourceConfig{
					{
						Type: shield.ResourceTypeOrganization,
						Roles: []*domain.Role{
							{
								ID:          "test-role",
								Permissions: []interface{}{"test-permission-config"},
							},
						},
					},
				},
				URN: providerURN,
			}
			a := domain.Grant{
				Resource: &domain.Resource{
					Type: shield.ResourceTypeOrganization,
					URN:  "organization:org_id",
					Name: "org_1",
					Details: map[string]interface{}{
						"id":     "org_id",
						"admins": []interface{}{"testAdmin@email.com"},
					},
				},
				Role:        "test-role",
				AccountID:   expectedUserEmail,
				Permissions: []string{"test-permission-config"},
			}

			actualError := p.GrantAccess(ctx, pc, a)

			assert.EqualError(t, actualError, expectedError.Error())
		})

		t.Run("should return nil error if granting access is successful", func(t *testing.T) {
			providerURN := "test-provider-urn"
			logger := log.NewCtxLogger("info", []string{"test"})
			client := new(mocks.ShieldClient)
			expectedOrganization := &shield.Organization{
				Name: "org_1",
				ID:   "org_id",
			}
			expectedUserEmail := "test@email.com"
			expectedUser := &shield.User{
				ID:    "test_user_id",
				Name:  "test_user",
				Email: expectedUserEmail,
			}

			expectedRole := "admins"
			p := shield.NewProvider("", logger)
			p.Clients = map[string]shield.ShieldClient{
				providerURN: client,
			}

			client.On("GetSelfUser", mockCtx, expectedUserEmail).Return(expectedUser, nil).Once()
			client.On("GrantOrganizationAccess", mockCtx, expectedOrganization, expectedUser.ID, expectedRole).Return(nil).Once()

			pc := &domain.ProviderConfig{
				Credentials: shield.Credentials{
					Host:      "localhost",
					AuthEmail: "test_email",
				},
				Resources: []*domain.ResourceConfig{
					{
						Type: shield.ResourceTypeOrganization,
						Roles: []*domain.Role{
							{
								ID:          "admin",
								Permissions: []interface{}{expectedRole},
							},
						},
					},
				},
				URN: providerURN,
			}
			a := domain.Grant{
				Resource: &domain.Resource{
					Type: shield.ResourceTypeOrganization,
					URN:  "organization:org_id",
					Name: "org_1",
					Details: map[string]interface{}{
						"id":     "org_id",
						"admins": []interface{}{"testAdmin@email.com"},
					},
				},
				Role:       "admin",
				AccountID:  expectedUserEmail,
				ResourceID: "999",
				ID:         "999",
			}

			actualError := p.GrantAccess(ctx, pc, a)

			assert.Nil(t, actualError)
		})
	})
}

func TestRevokeAccess(t *testing.T) {
	ctx := context.Background()
	mockCtx := mock.MatchedBy(func(ctx context.Context) bool { return true })
	t.Run("should return error if credentials is invalid", func(t *testing.T) {
		logger := log.NewCtxLogger("info", []string{"test"})
		p := shield.NewProvider("", logger)

		pc := &domain.ProviderConfig{
			Credentials: "invalid-credentials",
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

		actualError := p.RevokeAccess(ctx, pc, a)
		assert.Error(t, actualError)
	})

	t.Run("given resource type", func(t *testing.T) {
		expectedResource := &shield.Resource{
			Name: "test-resource",
			ID:   "test-id",
			Namespace: shield.Namespace{
				Name: "test-namespace",
				ID:   "test_namespace_id",
			},
		}
		providerURN := "test-provider-urn"
		client := new(mocks.ShieldClient)
		logger := log.NewCtxLogger("info", []string{"test"})
		expectedRole := "admins"
		p := shield.NewProvider("", logger)
		p.Clients = map[string]shield.ShieldClient{
			providerURN: client,
		}

		expectedUserEmail := "test@email.com"
		expectedUser := &shield.User{
			ID:    "test_user_id",
			Name:  "test_user",
			Email: expectedUserEmail,
		}
		pc := &domain.ProviderConfig{
			Credentials: shield.Credentials{
				Host:          "http://localhost/",
				AuthEmail:     "test_email",
				ClientVersion: "new",
			},
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
			URN: providerURN,
		}
		a := domain.Grant{
			Resource: &domain.Resource{
				Type: "test-type",
				Name: "test-resource",
				URN:  "resource:test-id",
				Details: map[string]interface{}{
					"id": "test_id",
					"namespace": map[string]interface{}{
						"name": "test-namespace",
						"id":   "test_namespace_id",
					},
				},
			},
			Role:        "admin",
			Permissions: []string{expectedRole},
			AccountID:   expectedUserEmail,
			ResourceID:  "999",
			ID:          "999",
		}
		t.Run("should return nil error if revoking resource access is successful", func(t *testing.T) {
			client.On("GetSelfUser", mockCtx, expectedUserEmail).Return(expectedUser, nil).Once()
			client.On("RevokeResourceAccess", mockCtx, expectedResource, expectedUser.ID, expectedRole).Return(nil).Once()

			actualError := p.RevokeAccess(ctx, pc, a)

			assert.Nil(t, actualError)
			client.AssertExpectations(t)
		})

		t.Run("should return error if there is an error in granting resource access", func(t *testing.T) {
			expectedError := errors.New("client error")

			client.On("GetSelfUser", mockCtx, expectedUserEmail).Return(expectedUser, nil).Once()
			client.On("GrantResourceAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(expectedError).Once()

			actualError := p.GrantAccess(ctx, pc, a)
			assert.EqualError(t, actualError, expectedError.Error())
		})
	})

	t.Run("given team resource", func(t *testing.T) {
		t.Run("should return error if there is an error in revoking team access", func(t *testing.T) {
			providerURN := "test-provider-urn"
			expectedError := errors.New("client error")
			client := new(mocks.ShieldClient)
			logger := log.NewCtxLogger("info", []string{"test"})
			p := shield.NewProvider("", logger)
			p.Clients = map[string]shield.ShieldClient{
				providerURN: client,
			}

			expectedUserEmail := "test@email.com"
			expectedUser := &shield.User{
				ID:    "test_user_id",
				Name:  "test_user",
				Email: expectedUserEmail,
			}

			client.On("GetSelfUser", mockCtx, expectedUserEmail).Return(expectedUser, nil).Once()
			client.On("RevokeGroupAccess", mockCtx, mock.Anything, mock.Anything, mock.Anything).Return(expectedError).Once()

			pc := &domain.ProviderConfig{
				Credentials: shield.Credentials{
					Host:      "localhost",
					AuthEmail: "test_email",
				},
				Resources: []*domain.ResourceConfig{
					{
						Type: shield.ResourceTypeTeam,
						Roles: []*domain.Role{
							{
								ID:          "test-role",
								Permissions: []interface{}{"test-permission-config"},
							},
						},
					},
				},
				URN: providerURN,
			}
			a := domain.Grant{
				Resource: &domain.Resource{
					Type: shield.ResourceTypeTeam,
					URN:  "team:team_id",
					Name: "team_1",
					Details: map[string]interface{}{
						"id":     "team_id",
						"orgId":  "456",
						"admins": []interface{}{"testAdmin@email.com"},
						"metadata": shield.Metadata{
							Email:   "team_1@gojek.com",
							Privacy: "public",
							Slack:   "team_1_slack",
						},
					},
				},
				Role:        "test-role",
				AccountID:   expectedUserEmail,
				Permissions: []string{"test-permission-config"},
			}

			actualError := p.RevokeAccess(ctx, pc, a)

			assert.EqualError(t, actualError, expectedError.Error())
		})

		t.Run("should return nil error if revoking team access is successful", func(t *testing.T) {
			providerURN := "test-provider-urn"
			logger := log.NewCtxLogger("info", []string{"test"})
			client := new(mocks.ShieldClient)
			expectedTeam := &shield.Group{
				Name:  "team_1",
				ID:    "team_id",
				OrgId: "456",
				Metadata: shield.Metadata{
					Email:   "team_1@gojek.com",
					Privacy: "public",
					Slack:   "team_1_slack",
				},
				Admins: []string{"testAdmin@email.com"},
			}

			expectedRole := "admins"
			p := shield.NewProvider("", logger)
			p.Clients = map[string]shield.ShieldClient{
				providerURN: client,
			}

			expectedUserEmail := "test@email.com"
			expectedUser := &shield.User{
				ID:    "test_user_id",
				Name:  "test_user",
				Email: expectedUserEmail,
			}

			client.On("GetSelfUser", mockCtx, expectedUserEmail).Return(expectedUser, nil).Once()
			client.On("RevokeGroupAccess", mockCtx, expectedTeam, expectedUser.ID, expectedRole).Return(nil).Once()

			pc := &domain.ProviderConfig{
				Credentials: shield.Credentials{
					Host:      "localhost",
					AuthEmail: "test_email",
				},
				Resources: []*domain.ResourceConfig{
					{
						Type: shield.ResourceTypeTeam,
						Roles: []*domain.Role{
							{
								ID:          "admin",
								Permissions: []interface{}{expectedRole},
							},
						},
					},
				},
				URN: providerURN,
			}
			a := domain.Grant{
				Resource: &domain.Resource{
					Type: shield.ResourceTypeTeam,
					URN:  "team:team_id",
					Name: "team_1",
					Details: map[string]interface{}{
						"id":     "team_id",
						"orgId":  "456",
						"admins": []interface{}{"testAdmin@email.com"},
						"metadata": shield.Metadata{
							Email:   "team_1@gojek.com",
							Privacy: "public",
							Slack:   "team_1_slack",
						},
					},
				},
				Role:        "admin",
				Permissions: []string{expectedRole},
				AccountID:   expectedUserEmail,
				ResourceID:  "999",
				ID:          "999",
			}

			actualError := p.RevokeAccess(ctx, pc, a)

			assert.Nil(t, actualError)
			client.AssertExpectations(t)
		})
	})

	t.Run("given project resource", func(t *testing.T) {
		t.Run("should return error if there is an error in revoking project access", func(t *testing.T) {
			providerURN := "test-provider-urn"
			expectedError := errors.New("client error")
			client := new(mocks.ShieldClient)
			logger := log.NewCtxLogger("info", []string{"test"})
			p := shield.NewProvider("", logger)
			p.Clients = map[string]shield.ShieldClient{
				providerURN: client,
			}

			expectedUserEmail := "test@email.com"
			expectedUser := &shield.User{
				ID:    "test_user_id",
				Name:  "test_user",
				Email: expectedUserEmail,
			}

			client.On("GetSelfUser", mockCtx, expectedUserEmail).Return(expectedUser, nil).Once()

			client.On("RevokeProjectAccess", mockCtx, mock.Anything, mock.Anything, mock.Anything).Return(expectedError).Once()

			pc := &domain.ProviderConfig{
				Credentials: shield.Credentials{
					Host:      "localhost",
					AuthEmail: "test_email",
				},
				Resources: []*domain.ResourceConfig{
					{
						Type: shield.ResourceTypeProject,
						Roles: []*domain.Role{
							{
								ID:          "test-role",
								Permissions: []interface{}{"test-permission-config"},
							},
						},
					},
				},
				URN: providerURN,
			}
			a := domain.Grant{
				Resource: &domain.Resource{
					Type: shield.ResourceTypeProject,
					URN:  "project:project_id",
					Name: "project_1",
					Details: map[string]interface{}{
						"id":     "project_id",
						"orgId":  "456",
						"admins": []interface{}{"testAdmin@email.com"},
					},
				},
				Role:        "test-role",
				AccountID:   expectedUserEmail,
				Permissions: []string{"test-permission-config"},
			}

			actualError := p.RevokeAccess(ctx, pc, a)

			assert.EqualError(t, actualError, expectedError.Error())
		})

		t.Run("should return nil error if revoking access is successful", func(t *testing.T) {
			providerURN := "test-provider-urn"
			client := new(mocks.ShieldClient)
			expectedProject := &shield.Project{
				Name:   "project_1",
				ID:     "project_id",
				OrgId:  "456",
				Admins: []string{"testAdmin@email.com"},
			}
			expectedRole := "admins"
			logger := log.NewCtxLogger("info", []string{"test"})
			p := shield.NewProvider("", logger)

			p.Clients = map[string]shield.ShieldClient{
				providerURN: client,
			}

			expectedUserEmail := "test@email.com"
			expectedUser := &shield.User{
				ID:    "test_user_id",
				Name:  "test_user",
				Email: expectedUserEmail,
			}

			client.On("GetSelfUser", mockCtx, expectedUserEmail).Return(expectedUser, nil).Once()
			client.On("RevokeProjectAccess", mockCtx, expectedProject, expectedUser.ID, expectedRole).Return(nil).Once()

			pc := &domain.ProviderConfig{
				Credentials: shield.Credentials{
					Host:      "localhost",
					AuthEmail: "test_email",
				},
				Resources: []*domain.ResourceConfig{
					{
						Type: shield.ResourceTypeProject,
						Roles: []*domain.Role{
							{
								ID:          "admin",
								Permissions: []interface{}{expectedRole},
							},
						},
					},
				},
				URN: providerURN,
			}
			a := domain.Grant{
				Resource: &domain.Resource{
					Type: shield.ResourceTypeProject,
					URN:  "project:project_id",
					Name: "project_1",
					Details: map[string]interface{}{
						"id":     "project_id",
						"orgId":  "456",
						"admins": []interface{}{"testAdmin@email.com"},
					},
				},
				Role:        "admin",
				Permissions: []string{expectedRole},
				AccountID:   expectedUserEmail,
				ResourceID:  "999",
				ID:          "999",
			}

			actualError := p.RevokeAccess(ctx, pc, a)

			assert.Nil(t, actualError)
			client.AssertExpectations(t)
		})
	})

	t.Run("given Organization resource", func(t *testing.T) {
		t.Run("should return error if there is an error in revoking organization access", func(t *testing.T) {
			providerURN := "test-provider-urn"
			expectedError := errors.New("client error")
			client := new(mocks.ShieldClient)
			logger := log.NewCtxLogger("info", []string{"test"})
			p := shield.NewProvider("", logger)
			p.Clients = map[string]shield.ShieldClient{
				providerURN: client,
			}

			expectedUserEmail := "test@email.com"
			expectedUser := &shield.User{
				ID:    "test_user_id",
				Name:  "test_user",
				Email: expectedUserEmail,
			}

			client.On("GetSelfUser", mockCtx, expectedUserEmail).Return(expectedUser, nil).Once()
			client.On("RevokeOrganizationAccess", mockCtx, mock.Anything, mock.Anything, mock.Anything).Return(expectedError).Once()

			pc := &domain.ProviderConfig{
				Credentials: shield.Credentials{
					Host:      "localhost",
					AuthEmail: "test_email",
				},
				Resources: []*domain.ResourceConfig{
					{
						Type: shield.ResourceTypeOrganization,
						Roles: []*domain.Role{
							{
								ID:          "test-role",
								Permissions: []interface{}{"test-permission-config"},
							},
						},
					},
				},
				URN: providerURN,
			}

			a := domain.Grant{
				Resource: &domain.Resource{
					Type: shield.ResourceTypeOrganization,
					URN:  "organization:org_id",
					Name: "org_1",
					Details: map[string]interface{}{
						"id":     "org_id",
						"admins": []interface{}{"testAdmin@email.com"},
					},
				},
				Role:        "test-role",
				AccountID:   expectedUserEmail,
				Permissions: []string{"test-permission-config"},
			}

			actualError := p.RevokeAccess(ctx, pc, a)

			assert.EqualError(t, actualError, expectedError.Error())
		})

		t.Run("should return nil error if revoking access is successful", func(t *testing.T) {
			providerURN := "test-provider-urn"
			client := new(mocks.ShieldClient)
			expectedOrganization := &shield.Organization{
				Name:   "org_1",
				ID:     "org_id",
				Admins: []string{"testAdmin@email.com"},
			}
			expectedRole := "admins"
			logger := log.NewCtxLogger("info", []string{"test"})
			p := shield.NewProvider("", logger)

			p.Clients = map[string]shield.ShieldClient{
				providerURN: client,
			}
			expectedUserEmail := "test@email.com"
			expectedUser := &shield.User{
				ID:    "test_user_id",
				Name:  "test_user",
				Email: expectedUserEmail,
			}

			client.On("GetSelfUser", mockCtx, expectedUserEmail).Return(expectedUser, nil).Once()
			client.On("RevokeOrganizationAccess", mockCtx, expectedOrganization, expectedUser.ID, expectedRole).Return(nil).Once()

			pc := &domain.ProviderConfig{
				Credentials: shield.Credentials{
					Host:      "localhost",
					AuthEmail: "test_email",
				},
				Resources: []*domain.ResourceConfig{
					{
						Type: shield.ResourceTypeOrganization,
						Roles: []*domain.Role{
							{
								ID:          "admin",
								Permissions: []interface{}{expectedRole},
							},
						},
					},
				},
				URN: providerURN,
			}
			a := domain.Grant{
				Resource: &domain.Resource{
					Type: shield.ResourceTypeOrganization,
					URN:  "organization:org_id",
					Name: "org_1",
					Details: map[string]interface{}{
						"id":     "org_id",
						"admins": []interface{}{"testAdmin@email.com"},
					},
				},
				Role:        "admin",
				Permissions: []string{expectedRole},
				AccountID:   expectedUserEmail,
				ResourceID:  "999",
				ID:          "999",
			}

			actualError := p.RevokeAccess(ctx, pc, a)

			assert.Nil(t, actualError)
			client.AssertExpectations(t)
		})
	})
}

func TestGetAccountTypes(t *testing.T) {
	expectedAccountType := []string{"user"}
	logger := log.NewCtxLogger("info", []string{"test"})
	p := shield.NewProvider("", logger)

	actualAccountType := p.GetAccountTypes()

	assert.Equal(t, expectedAccountType, actualAccountType)
}

func TestGetRoles(t *testing.T) {
	t.Run("should return error if resource type is invalid", func(t *testing.T) {
		logger := log.NewCtxLogger("info", []string{"test"})
		p := shield.NewProvider("shield", logger)
		validConfig := &domain.ProviderConfig{
			Type:                "shield",
			URN:                 "test-URN",
			AllowedAccountTypes: []string{"user"},
			Credentials:         map[string]interface{}{},
			Resources: []*domain.ResourceConfig{
				{
					Type: "team",
					Policy: &domain.PolicyConfig{
						ID:      "test-policy-1",
						Version: 1,
					},
				},
				{
					Type: "project",
					Policy: &domain.PolicyConfig{
						ID:      "test-policy-2",
						Version: 1,
					},
				},
				{
					Type: "organization",
					Policy: &domain.PolicyConfig{
						ID:      "test-policy-3",
						Version: 1,
					},
				},
			},
		}

		actualRoles, actualError := p.GetRoles(validConfig, "invalid_resource_type")

		assert.Nil(t, actualRoles)
		assert.ErrorIs(t, actualError, provider.ErrInvalidResourceType)
	})

	t.Run("should return roles specified in the provider config", func(t *testing.T) {
		logger := log.NewCtxLogger("info", []string{"test"})
		p := shield.NewProvider("shield", logger)

		expectedRoles := []*domain.Role{
			{
				ID:   "test-role",
				Name: "test_role_name",
			},
		}

		validConfig := &domain.ProviderConfig{
			Type:                "shield",
			URN:                 "test-URN",
			AllowedAccountTypes: []string{"user"},
			Credentials:         map[string]interface{}{},
			Resources: []*domain.ResourceConfig{
				{
					Type: "team",
					Policy: &domain.PolicyConfig{
						ID:      "test-policy-1",
						Version: 1,
					},
					Roles: expectedRoles,
				},
			},
		}

		actualRoles, actualError := p.GetRoles(validConfig, "team")

		assert.NoError(t, actualError)
		assert.Equal(t, expectedRoles, actualRoles)
	})
}
func TestGetClient(t *testing.T) {
	t.Run("should return existing client if already present", func(t *testing.T) {
		providerURN := "test-provider-urn"
		expectedClient := new(mocks.ShieldClient)
		logger := log.NewCtxLogger("info", []string{"test"})
		p := shield.NewProvider("shield", logger)
		p.Clients = map[string]shield.ShieldClient{
			providerURN: expectedClient,
		}

		creds := shield.Credentials{
			Host:       "localhost",
			AuthEmail:  "test-email",
			AuthHeader: "test-header",
		}

		actualClient, err := p.GetClient(providerURN, creds)

		assert.NoError(t, err)
		assert.Equal(t, expectedClient, actualClient)
	})

	t.Run("should return new client of old shield if not already present", func(t *testing.T) {
		providerURN := "test-provider-urn"
		logger := log.NewCtxLogger("info", []string{"test"})
		p := shield.NewProvider("", logger)

		creds := shield.Credentials{
			Host:       "http://localhost.com",
			AuthEmail:  "test-email",
			AuthHeader: "test-header",
		}

		_, err := p.GetClient(providerURN, creds)
		assert.NoError(t, err)
	})

	t.Run("should return new client of new shield if not already present", func(t *testing.T) {
		providerURN := "test-provider-urn"
		logger := log.NewCtxLogger("info", []string{"test"})
		p := shield.NewProvider("", logger)

		creds := shield.Credentials{
			Host:          "http://localhost.com",
			AuthEmail:     "test-email",
			ClientVersion: "new",
			AuthHeader:    "test-header",
		}

		_, err := p.GetClient(providerURN, creds)

		assert.NoError(t, err)
	})
}

func TestValidateResourceIdentifiers(t *testing.T) {
	logger := log.NewCtxLogger("info", []string{"test"})

	t.Run("should return error for unsupported resource type", func(t *testing.T) {
		p := shield.NewProvider("shield", logger)
		r := &domain.Resource{
			Type: "unsupported_type",
			URN:  "some-urn",
		}
		err := p.ValidateResourceIdentifiers(context.Background(), r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported resource type")
	})

	t.Run("should return error when URN is empty", func(t *testing.T) {
		p := shield.NewProvider("shield", logger)
		for _, rt := range []string{
			shield.ResourceTypeTeam,
			shield.ResourceTypeProject,
			shield.ResourceTypeOrganization,
			shield.ResourceTypeResource,
			shield.ResourceTypeCreateTeam,
		} {
			err := p.ValidateResourceIdentifiers(context.Background(), &domain.Resource{Type: rt, URN: ""})
			assert.Errorf(t, err, "expected error for resource type %q with empty URN", rt)
			assert.Contains(t, err.Error(), "urn is required")
		}
	})

	t.Run("should return nil for all supported resource types with non-empty URN", func(t *testing.T) {
		p := shield.NewProvider("shield", logger)
		for _, rt := range []string{
			shield.ResourceTypeTeam,
			shield.ResourceTypeProject,
			shield.ResourceTypeOrganization,
			shield.ResourceTypeResource,
			shield.ResourceTypeCreateTeam,
		} {
			err := p.ValidateResourceIdentifiers(context.Background(), &domain.Resource{Type: rt, URN: "valid-urn"})
			assert.NoErrorf(t, err, "unexpected error for resource type %q", rt)
		}
	})
}

func TestValidateResourceDetails(t *testing.T) {
	logger := log.NewCtxLogger("info", []string{"test"})
	p := shield.NewProvider("shield", logger)

	t.Run("should always return nil", func(t *testing.T) {
		err := p.ValidateResourceDetails(context.Background(), &domain.Resource{Type: shield.ResourceTypeTeam})
		assert.NoError(t, err)
	})
}

func TestValidateAppeal(t *testing.T) {
	providerURN := "test-provider-urn"
	logger := log.NewCtxLogger("info", []string{"test"})

	newProvider := func(urn string) *domain.Provider {
		return &domain.Provider{
			URN: urn,
			Config: &domain.ProviderConfig{
				URN: urn,
				Credentials: shield.Credentials{
					Host:       "https://shield.test",
					AuthHeader: "X-Auth-Email",
					AuthEmail:  "admin@test.com",
				},
			},
		}
	}
	pr := newProvider(providerURN)

	t.Run("should return nil for non create_team resource types", func(t *testing.T) {
		p := shield.NewProvider("shield", logger)
		appeal := &domain.Appeal{
			Resource: &domain.Resource{Type: shield.ResourceTypeTeam, ProviderURN: providerURN},
			Details:  map[string]interface{}{},
		}
		assert.NoError(t, p.ValidateAppeal(context.Background(), appeal, pr))
	})

	t.Run("should return nil when resource is nil", func(t *testing.T) {
		p := shield.NewProvider("shield", logger)
		appeal := &domain.Appeal{Resource: nil}
		assert.NoError(t, p.ValidateAppeal(context.Background(), appeal, pr))
	})

	t.Run("should return error when team_name is missing", func(t *testing.T) {
		client := new(mocks.ShieldClient)
		p := shield.NewProvider("shield", logger)
		p.Clients = map[string]shield.ShieldClient{providerURN: client}

		appeal := &domain.Appeal{
			Resource: &domain.Resource{Type: shield.ResourceTypeCreateTeam, ProviderURN: providerURN},
			Details:  map[string]interface{}{},
		}
		err := p.ValidateAppeal(context.Background(), appeal, pr)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "team_name is required")
	})

	t.Run("should return error when provider config is nil", func(t *testing.T) {
		p := shield.NewProvider("shield", logger)

		appeal := &domain.Appeal{
			Resource: &domain.Resource{Type: shield.ResourceTypeCreateTeam, ProviderURN: providerURN},
			Details:  map[string]interface{}{"team_name": "My Team"},
		}
		err := p.ValidateAppeal(context.Background(), appeal, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "provider config is required")
	})

	t.Run("should return error when GetGroups fails", func(t *testing.T) {
		client := new(mocks.ShieldClient)
		p := shield.NewProvider("shield", logger)
		p.Clients = map[string]shield.ShieldClient{providerURN: client}

		client.On("GetGroups", mock.Anything).Return(nil, errors.New("shield unavailable")).Once()

		appeal := &domain.Appeal{
			Resource: &domain.Resource{Type: shield.ResourceTypeCreateTeam, ProviderURN: providerURN},
			Details:  map[string]interface{}{"team_name": "My Team"},
		}
		err := p.ValidateAppeal(context.Background(), appeal, pr)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "fetching existing teams from shield")
		client.AssertExpectations(t)
	})

	t.Run("should return error when a team with the same name already exists", func(t *testing.T) {
		client := new(mocks.ShieldClient)
		p := shield.NewProvider("shield", logger)
		p.Clients = map[string]shield.ShieldClient{providerURN: client}

		existingGroups := []*shield.Group{
			{ID: "existing-id", Name: "My Team", Slug: "my_team"},
		}
		client.On("GetGroups", mock.Anything).Return(existingGroups, nil).Once()

		appeal := &domain.Appeal{
			Resource: &domain.Resource{Type: shield.ResourceTypeCreateTeam, ProviderURN: providerURN},
			Details:  map[string]interface{}{"team_name": "My Team"},
		}
		err := p.ValidateAppeal(context.Background(), appeal, pr)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
		client.AssertExpectations(t)
	})

	t.Run("should return error when a team with the same name exists case-insensitively", func(t *testing.T) {
		client := new(mocks.ShieldClient)
		p := shield.NewProvider("shield", logger)
		p.Clients = map[string]shield.ShieldClient{providerURN: client}

		existingGroups := []*shield.Group{
			{ID: "existing-id", Name: "my team", Slug: "my_team"},
		}
		client.On("GetGroups", mock.Anything).Return(existingGroups, nil).Once()

		appeal := &domain.Appeal{
			Resource: &domain.Resource{Type: shield.ResourceTypeCreateTeam, ProviderURN: providerURN},
			Details:  map[string]interface{}{"team_name": "MY TEAM"},
		}
		err := p.ValidateAppeal(context.Background(), appeal, pr)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
		client.AssertExpectations(t)
	})

	t.Run("should return error when a team with the same slug already exists", func(t *testing.T) {
		client := new(mocks.ShieldClient)
		p := shield.NewProvider("shield", logger)
		p.Clients = map[string]shield.ShieldClient{providerURN: client}

		existingGroups := []*shield.Group{
			{ID: "existing-id", Name: "Existing Team", Slug: "new_team"},
		}
		client.On("GetGroups", mock.Anything).Return(existingGroups, nil).Once()

		appeal := &domain.Appeal{
			Resource: &domain.Resource{Type: shield.ResourceTypeCreateTeam, ProviderURN: providerURN},
			Details:  map[string]interface{}{"team_name": "New Team", "slug": "new_team"},
		}
		err := p.ValidateAppeal(context.Background(), appeal, pr)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "slug")
		assert.Contains(t, err.Error(), "already exists")
		client.AssertExpectations(t)
	})

	t.Run("should return nil when team name and slug are unique", func(t *testing.T) {
		client := new(mocks.ShieldClient)
		p := shield.NewProvider("shield", logger)
		p.Clients = map[string]shield.ShieldClient{providerURN: client}

		existingGroups := []*shield.Group{
			{ID: "other-id", Name: "Other Team", Slug: "other_team"},
		}
		client.On("GetGroups", mock.Anything).Return(existingGroups, nil).Once()

		appeal := &domain.Appeal{
			Resource: &domain.Resource{Type: shield.ResourceTypeCreateTeam, ProviderURN: providerURN},
			Details:  map[string]interface{}{"team_name": "My New Team", "slug": "my_new_team"},
		}
		err := p.ValidateAppeal(context.Background(), appeal, pr)
		assert.NoError(t, err)
		client.AssertExpectations(t)
	})

	t.Run("should auto-generate slug from team_name when slug not provided", func(t *testing.T) {
		client := new(mocks.ShieldClient)
		p := shield.NewProvider("shield", logger)
		p.Clients = map[string]shield.ShieldClient{providerURN: client}

		existingGroups := []*shield.Group{
			{ID: "other-id", Name: "Other Team", Slug: "other_team"},
		}
		client.On("GetGroups", mock.Anything).Return(existingGroups, nil).Once()

		appeal := &domain.Appeal{
			Resource: &domain.Resource{Type: shield.ResourceTypeCreateTeam, ProviderURN: providerURN},
			Details:  map[string]interface{}{"team_name": "My Brand New Team"},
		}
		err := p.ValidateAppeal(context.Background(), appeal, pr)
		assert.NoError(t, err)
		client.AssertExpectations(t)
	})
}

func TestGrantAccessCreateTeam(t *testing.T) {
	ctx := context.Background()
	mockCtx := mock.MatchedBy(func(ctx context.Context) bool { return true })
	providerURN := "test-provider-urn"
	logger := log.NewCtxLogger("info", []string{"test"})

	basePC := &domain.ProviderConfig{
		Credentials: shield.Credentials{
			Host:      "localhost",
			AuthEmail: "test_email",
		},
		Resources: []*domain.ResourceConfig{
			{
				Type: shield.ResourceTypeCreateTeam,
				Roles: []*domain.Role{
					{ID: "creator", Permissions: []interface{}{"create"}},
				},
			},
		},
		URN: providerURN,
	}

	t.Run("should return error when appeal is nil", func(t *testing.T) {
		client := new(mocks.ShieldClient)
		p := shield.NewProvider("shield", logger)
		p.Clients = map[string]shield.ShieldClient{providerURN: client}

		expectedUser := &shield.User{ID: "user_id", Email: "user@test.com"}
		client.On("GetSelfUser", mockCtx, "user@test.com").Return(expectedUser, nil).Once()

		a := domain.Grant{
			Resource:  &domain.Resource{Type: shield.ResourceTypeCreateTeam},
			AccountID: "user@test.com",
			Appeal:    nil,
		}
		err := p.GrantAccess(ctx, basePC, a)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "appeal details are required")
	})

	t.Run("should return error when team_name is missing from appeal details", func(t *testing.T) {
		client := new(mocks.ShieldClient)
		p := shield.NewProvider("shield", logger)
		p.Clients = map[string]shield.ShieldClient{providerURN: client}

		expectedUser := &shield.User{ID: "user_id", Email: "user@test.com"}
		client.On("GetSelfUser", mockCtx, "user@test.com").Return(expectedUser, nil).Once()

		a := domain.Grant{
			Resource:  &domain.Resource{Type: shield.ResourceTypeCreateTeam},
			AccountID: "user@test.com",
			Appeal:    &domain.Appeal{Details: map[string]interface{}{}},
		}
		err := p.GrantAccess(ctx, basePC, a)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "team_name is required")
	})

	t.Run("should return error when GrantCreateTeamAccess fails", func(t *testing.T) {
		client := new(mocks.ShieldClient)
		p := shield.NewProvider("shield", logger)
		p.Clients = map[string]shield.ShieldClient{providerURN: client}

		expectedUser := &shield.User{ID: "user_id", Email: "user@test.com"}
		client.On("GetSelfUser", mockCtx, "user@test.com").Return(expectedUser, nil).Once()
		client.On("GrantCreateTeamAccess", mockCtx, mock.Anything, "user_id").Return(nil, errors.New("shield error")).Once()

		a := domain.Grant{
			Resource:  &domain.Resource{Type: shield.ResourceTypeCreateTeam},
			AccountID: "user@test.com",
			Appeal: &domain.Appeal{Details: map[string]interface{}{
				"team_name": "My Team",
				"org_id":    "org-123",
				"slug":      "my_team",
			}},
		}
		err := p.GrantAccess(ctx, basePC, a)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "shield error")
		client.AssertExpectations(t)
	})

	t.Run("should return nil when GrantCreateTeamAccess succeeds", func(t *testing.T) {
		client := new(mocks.ShieldClient)
		p := shield.NewProvider("shield", logger)
		p.Clients = map[string]shield.ShieldClient{providerURN: client}

		expectedUser := &shield.User{ID: "user_id", Email: "user@test.com"}
		createdGroup := &shield.Group{ID: "new-team-id", Name: "My Team", Slug: "my_team"}
		client.On("GetSelfUser", mockCtx, "user@test.com").Return(expectedUser, nil).Once()
		client.On("GrantCreateTeamAccess", mockCtx, mock.MatchedBy(func(g shield.Group) bool {
			return g.Name == "My Team" && g.Slug == "my_team" && g.OrgId == "org-123"
		}), "user_id").Return(createdGroup, nil).Once()

		a := domain.Grant{
			Resource:  &domain.Resource{Type: shield.ResourceTypeCreateTeam},
			AccountID: "user@test.com",
			Appeal: &domain.Appeal{Details: map[string]interface{}{
				"team_name": "My Team",
				"org_id":    "org-123",
				"slug":      "my_team",
			}},
		}
		err := p.GrantAccess(ctx, basePC, a)
		assert.NoError(t, err)
		client.AssertExpectations(t)
	})

	t.Run("should auto-generate slug when not provided in appeal details", func(t *testing.T) {
		client := new(mocks.ShieldClient)
		p := shield.NewProvider("shield", logger)
		p.Clients = map[string]shield.ShieldClient{providerURN: client}

		expectedUser := &shield.User{ID: "user_id", Email: "user@test.com"}
		createdGroup := &shield.Group{ID: "new-team-id", Name: "My Team", Slug: "my_team"}
		client.On("GetSelfUser", mockCtx, "user@test.com").Return(expectedUser, nil).Once()
		client.On("GrantCreateTeamAccess", mockCtx, mock.MatchedBy(func(g shield.Group) bool {
			return g.Name == "My Team" && g.Slug == "my_team"
		}), "user_id").Return(createdGroup, nil).Once()

		a := domain.Grant{
			Resource:  &domain.Resource{Type: shield.ResourceTypeCreateTeam},
			AccountID: "user@test.com",
			Appeal: &domain.Appeal{Details: map[string]interface{}{
				"team_name": "My Team",
				"org_id":    "org-123",
			}},
		}
		err := p.GrantAccess(ctx, basePC, a)
		assert.NoError(t, err)
		client.AssertExpectations(t)
	})
}
