package gitlab_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/plugins/providers/gitlab"
	"github.com/goto/guardian/plugins/providers/gitlab/mocks"
	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	listGroupsEndpoint        = "/api/v4/groups"
	addGroupMemberEndpoint    = func(gID string) string { return fmt.Sprintf("/api/v4/groups/%s/members", gID) }
	editGroupMemberEndpoint   = func(gID, uID string) string { return fmt.Sprintf("/api/v4/groups/%s/members/%s", gID, uID) }
	deleteGroupMemberEndpoint = func(gID, uID string) string { return fmt.Sprintf("/api/v4/groups/%s/members/%s", gID, uID) }

	listProjectsEndpoint        = "/api/v4/projects"
	addProjectMemberEndpoint    = func(pID string) string { return fmt.Sprintf("/api/v4/projects/%s/members", pID) }
	editProjectMemberEndpoint   = func(pID, uID string) string { return fmt.Sprintf("/api/v4/projects/%s/members/%s", pID, uID) }
	deleteProjectMemberEndpoint = func(pID, uID string) string { return fmt.Sprintf("/api/v4/projects/%s/members/%s", pID, uID) }
)

func TestGetType(t *testing.T) {
	t.Run("should return set provider type", func(t *testing.T) {
		expectedProviderType := "gitlab"
		provider := gitlab.NewProvider(expectedProviderType, nil, log.NewNoop())
		assert.Equal(t, expectedProviderType, provider.GetType())
	})
}

func TestCreateConfig(t *testing.T) {
	t.Run("should encrypt sensitive value(s) in provider config", func(t *testing.T) {
		encryptor := new(mocks.Encryptor)
		logger := log.NewNoop()
		gitlabProvider := gitlab.NewProvider("gitlab", encryptor, logger)

		pc := &domain.ProviderConfig{
			Type: "gitlab",
			URN:  "test-gitlab",
			Credentials: map[string]interface{}{
				"host":         "https://gitlab.com",
				"access_token": "test-token",
			},
			Resources: []*domain.ResourceConfig{
				{
					Type:   "group",
					Policy: &domain.PolicyConfig{ID: "test-policy", Version: 1},
					Roles: []*domain.Role{
						{ID: "test-developer-role", Permissions: []interface{}{"developer"}},
					},
				},
			},
		}

		expectedEncryptedToken := "encrypted-token"
		encryptor.EXPECT().Encrypt("test-token").Return(expectedEncryptedToken, nil)
		defer encryptor.AssertExpectations(t)

		err := gitlabProvider.CreateConfig(pc)
		assert.NoError(t, err)

		// read encrypted token from credentials
		var credsMap map[string]interface{}
		err = mapstructure.Decode(pc.Credentials, &credsMap)
		require.NoError(t, err)

		assert.Equal(t, expectedEncryptedToken, credsMap["access_token"])
	})
}

func TestGetResources(t *testing.T) {
	t.Run("should return gitlab resources on success", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc(listGroupsEndpoint, func(w http.ResponseWriter, r *http.Request) {
			groups, err := readFixtures("testdata/groups/page_1.json")
			require.NoError(t, err)
			w.WriteHeader(http.StatusOK)
			w.Write(groups)
		})
		mux.HandleFunc(listProjectsEndpoint, func(w http.ResponseWriter, r *http.Request) {
			groups, err := readFixtures("testdata/projects/page_1.json")
			require.NoError(t, err)
			w.WriteHeader(http.StatusOK)
			w.Write(groups)
		})
		ts := httptest.NewServer(mux)
		defer ts.Close()

		encryptor := new(mocks.Encryptor)
		logger := log.NewNoop()
		gitlabProvider := gitlab.NewProvider("gitlab", encryptor, logger)

		encryptor.EXPECT().Decrypt("encrypted-token").Return("test-token", nil)
		defer encryptor.AssertExpectations(t)

		pc := &domain.ProviderConfig{
			Type: "gitlab",
			URN:  "test-gitlab",
			Credentials: map[string]interface{}{
				"host":         ts.URL,
				"access_token": "encrypted-token",
			},
			Resources: []*domain.ResourceConfig{
				{
					Type:   "group",
					Policy: &domain.PolicyConfig{ID: "test-policy", Version: 1},
					Roles: []*domain.Role{
						{ID: "test-developer-role", Permissions: []interface{}{"developer"}},
					},
				},
				{
					Type:   "project",
					Policy: &domain.PolicyConfig{ID: "test-policy", Version: 1},
					Roles: []*domain.Role{
						{ID: "test-developer-role", Permissions: []interface{}{"developer"}},
					},
				},
			},
		}
		resources, err := gitlabProvider.GetResources(context.Background(), pc)

		assert.NoError(t, err)
		assert.NotEmpty(t, resources)
	})

	t.Run("pagination", func(t *testing.T) {
		var groupFixtures []map[string]interface{}

		mux := http.NewServeMux()
		mux.HandleFunc(listGroupsEndpoint, func(w http.ResponseWriter, r *http.Request) {
			page := r.URL.Query().Get("page")

			var groups []byte
			var err error
			switch page {
			case "1":
				groups, err = readFixtures("testdata/groups/page_1.json")
				w.Header().Set("X-Page", "1")
				w.Header().Set("X-Next-Page", "2")
			case "2":
				groups, err = readFixtures("testdata/groups/page_2.json")
				w.Header().Set("X-Page", "2")
			}
			w.Header().Set("X-Total-Pages", "2")
			require.NoError(t, err)

			//
			var records []map[string]interface{}
			err = json.Unmarshal(groups, &records)
			require.NoError(t, err)
			groupFixtures = append(groupFixtures, records...)

			w.WriteHeader(http.StatusOK)
			w.Write(groups)
		})
		ts := httptest.NewServer(mux)
		defer ts.Close()

		encryptor := new(mocks.Encryptor)
		logger := log.NewNoop()
		gitlabProvider := gitlab.NewProvider("gitlab", encryptor, logger)

		encryptor.EXPECT().Decrypt("encrypted-token").Return("test-token", nil)
		defer encryptor.AssertExpectations(t)

		pc := &domain.ProviderConfig{
			Type: "gitlab",
			URN:  "test-gitlab",
			Credentials: map[string]interface{}{
				"host":         ts.URL,
				"access_token": "encrypted-token",
			},
			Resources: []*domain.ResourceConfig{
				{
					Type:   "group",
					Policy: &domain.PolicyConfig{ID: "test-policy", Version: 1},
					Roles: []*domain.Role{
						{ID: "test-developer-role", Permissions: []interface{}{"developer"}},
					},
				},
			},
		}
		resources, err := gitlabProvider.GetResources(context.Background(), pc)

		assert.NoError(t, err)
		assert.Len(t, resources, len(groupFixtures))
	})
}

func TestGrantAcccess(t *testing.T) {
	t.Run("should grant access to gitlab resources on success", func(t *testing.T) {
		testCases := []struct {
			name     string
			grant    domain.Grant
			handlers map[string]http.HandlerFunc // map[endpoint]handler
		}{
			{
				name: "should add access to group for new member",
				grant: domain.Grant{
					AccountID:   "99",
					Permissions: []string{"developer"},
					Resource:    &domain.Resource{Type: "group", URN: "1"},
				},
				handlers: map[string]http.HandlerFunc{
					addGroupMemberEndpoint("1"): func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusCreated)
						w.Write([]byte("{}"))
					},
				},
			},
			{
				name: "should edit access to group for existing member",
				grant: domain.Grant{
					AccountID:   "99",
					Permissions: []string{"developer"},
					Resource:    &domain.Resource{Type: "group", URN: "1"},
				},
				handlers: map[string]http.HandlerFunc{
					addGroupMemberEndpoint("1"): func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusConflict)
						w.Write([]byte(`{"message": "Member already exists"}`))
					},
					editGroupMemberEndpoint("1", "99"): func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte("{}"))
					},
				},
			},
			{
				name: "should add access to project for new member",
				grant: domain.Grant{
					AccountID:   "99",
					Permissions: []string{"developer"},
					Resource:    &domain.Resource{Type: "project", URN: "1"},
				},
				handlers: map[string]http.HandlerFunc{
					addProjectMemberEndpoint("1"): func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusCreated)
						w.Write([]byte("{}"))
					},
				},
			},
			{
				name: "should edit access to group for existing member",
				grant: domain.Grant{
					AccountID:   "99",
					Permissions: []string{"developer"},
					Resource:    &domain.Resource{Type: "project", URN: "1"},
				},
				handlers: map[string]http.HandlerFunc{
					addProjectMemberEndpoint("1"): func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusConflict)
						w.Write([]byte(`{"message": "Member already exists"}`))
					},
					editProjectMemberEndpoint("1", "99"): func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte("{}"))
					},
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				mux := http.NewServeMux()
				for endpoint, handler := range tc.handlers {
					mux.HandleFunc(endpoint, handler)
				}
				ts := httptest.NewServer(mux)
				defer ts.Close()

				encryptor := new(mocks.Encryptor)
				logger := log.NewNoop()
				gitlabProvider := gitlab.NewProvider("gitlab", encryptor, logger)

				encryptor.EXPECT().Decrypt("encrypted-token").Return("test-token", nil)
				defer encryptor.AssertExpectations(t)

				pc := &domain.ProviderConfig{
					Type: "gitlab",
					URN:  "test-gitlab",
					Credentials: map[string]interface{}{
						"host":         ts.URL,
						"access_token": "encrypted-token",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type:   "group",
							Policy: &domain.PolicyConfig{ID: "test-policy", Version: 1},
							Roles: []*domain.Role{
								{ID: "test-developer-role", Permissions: []interface{}{"developer"}},
							},
						},
						{
							Type:   "project",
							Policy: &domain.PolicyConfig{ID: "test-policy", Version: 1},
							Roles: []*domain.Role{
								{ID: "test-developer-role", Permissions: []interface{}{"developer"}},
							},
						},
					},
				}

				err := gitlabProvider.GrantAccess(context.Background(), pc, tc.grant)
				assert.NoError(t, err)
			})
		}
	})
}

func TestRevokeAccess(t *testing.T) {
	t.Run("should revoke access to gitlab resources on success", func(t *testing.T) {
		testCases := []struct {
			name     string
			grant    domain.Grant
			handlers map[string]http.HandlerFunc // map[endpoint]handler
		}{
			{
				name: "should remove access to group for existing member",
				grant: domain.Grant{
					AccountID:   "99",
					Permissions: []string{"developer"},
					Resource:    &domain.Resource{Type: "group", URN: "1"},
				},
				handlers: map[string]http.HandlerFunc{
					deleteGroupMemberEndpoint("1", "99"): func(w http.ResponseWriter, r *http.Request) {
						if r.Method != http.MethodDelete {
							w.WriteHeader(http.StatusMethodNotAllowed)
							w.Write(nil)
							return
						}
						w.WriteHeader(http.StatusNoContent)
						w.Write([]byte(""))
					},
				},
			},
			{
				name: "should not return error if member does not exist in group",
				grant: domain.Grant{
					AccountID:   "99",
					Permissions: []string{"developer"},
					Resource:    &domain.Resource{Type: "group", URN: "1"},
				},
				handlers: map[string]http.HandlerFunc{
					deleteGroupMemberEndpoint("1", "99"): func(w http.ResponseWriter, r *http.Request) {
						if r.Method != http.MethodDelete {
							w.WriteHeader(http.StatusMethodNotAllowed)
							w.Write(nil)
							return
						}
						w.WriteHeader(http.StatusNotFound)
						w.Write([]byte(`{"message": "404 Not found"}`))
					},
				},
			},
			{
				name: "should remove access to project for existing member",
				grant: domain.Grant{
					AccountID:   "99",
					Permissions: []string{"developer"},
					Resource:    &domain.Resource{Type: "project", URN: "1"},
				},
				handlers: map[string]http.HandlerFunc{
					deleteProjectMemberEndpoint("1", "99"): func(w http.ResponseWriter, r *http.Request) {
						if r.Method != http.MethodDelete {
							w.WriteHeader(http.StatusMethodNotAllowed)
							w.Write(nil)
							return
						}
						w.WriteHeader(http.StatusNoContent)
						w.Write([]byte(""))
					},
				},
			},
			{
				name: "should not return error if member does not exist in project",
				grant: domain.Grant{
					AccountID:   "99",
					Permissions: []string{"developer"},
					Resource:    &domain.Resource{Type: "project", URN: "1"},
				},
				handlers: map[string]http.HandlerFunc{
					deleteProjectMemberEndpoint("1", "99"): func(w http.ResponseWriter, r *http.Request) {
						if r.Method != http.MethodDelete {
							w.WriteHeader(http.StatusMethodNotAllowed)
							w.Write(nil)
							return
						}
						w.WriteHeader(http.StatusNotFound)
						w.Write([]byte(`{"message": "404 Not found"}`))
					},
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				mux := http.NewServeMux()
				for endpoint, handler := range tc.handlers {
					mux.HandleFunc(endpoint, handler)
				}
				ts := httptest.NewServer(mux)
				defer ts.Close()

				encryptor := new(mocks.Encryptor)
				logger := log.NewNoop()
				gitlabProvider := gitlab.NewProvider("gitlab", encryptor, logger)

				encryptor.EXPECT().Decrypt("encrypted-token").Return("test-token", nil)
				defer encryptor.AssertExpectations(t)

				pc := &domain.ProviderConfig{
					Type: "gitlab",
					URN:  "test-gitlab",
					Credentials: map[string]interface{}{
						"host":         ts.URL,
						"access_token": "encrypted-token",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type:   "group",
							Policy: &domain.PolicyConfig{ID: "test-policy", Version: 1},
							Roles: []*domain.Role{
								{ID: "test-developer-role", Permissions: []interface{}{"developer"}},
							},
						},
						{
							Type:   "project",
							Policy: &domain.PolicyConfig{ID: "test-policy", Version: 1},
							Roles: []*domain.Role{
								{ID: "test-developer-role", Permissions: []interface{}{"developer"}},
							},
						},
					},
				}

				err := gitlabProvider.RevokeAccess(context.Background(), pc, tc.grant)
				assert.NoError(t, err)
			})
		}
	})
}

func TestGetRoles(t *testing.T) {
	t.Run("should return registered provider roles", func(t *testing.T) {
		groupRoles := []*domain.Role{
			{ID: "test-developer-role", Permissions: []interface{}{"developer"}},
			{ID: "test-maintainer-role", Permissions: []interface{}{"maintainer"}},
		}
		projectRoles := []*domain.Role{
			{ID: "test-developer-role", Permissions: []interface{}{"developer"}},
			{ID: "test-maintainer-role", Permissions: []interface{}{"maintainer"}},
			{ID: "test-owner-role", Permissions: []interface{}{"owner"}},
		}
		pc := &domain.ProviderConfig{
			Type: "gitlab",
			URN:  "test-gitlab",
			Resources: []*domain.ResourceConfig{
				{
					Type:   "group",
					Policy: &domain.PolicyConfig{ID: "test-policy", Version: 1},
					Roles:  groupRoles,
				},
				{
					Type:   "project",
					Policy: &domain.PolicyConfig{ID: "test-policy", Version: 1},
					Roles:  projectRoles,
				},
			},
		}

		provider := gitlab.NewProvider("gitlab", nil, log.NewNoop())
		roles, err := provider.GetRoles(pc, "group")
		assert.NoError(t, err)
		assert.Equal(t, groupRoles, roles)

		roles, err = provider.GetRoles(pc, "project")
		assert.NoError(t, err)
		assert.Equal(t, projectRoles, roles)
	})
}

func TestGetAccountTypes(t *testing.T) {
	t.Run("should return account types", func(t *testing.T) {
		provider := gitlab.NewProvider("gitlab", nil, log.NewNoop())
		accountTypes := provider.GetAccountTypes()
		assert.Equal(t, []string{"gitlab_user_id"}, accountTypes)
	})
}

func TestIsExclusiveRoleAssignment(t *testing.T) {
	t.Run("should return exclusive role assignment state = true", func(t *testing.T) {
		provider := gitlab.NewProvider("gitlab", nil, log.NewNoop())
		assert.True(t, provider.IsExclusiveRoleAssignment(context.Background()))
	})
}

func readFixtures(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
