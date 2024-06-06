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
	groupsEndpoint             = "/api/v4/groups"
	groupProjectsEndpoint      = func(gID string) string { return fmt.Sprintf("/api/v4/groups/%s/projects", gID) }
	groupMembersEndpoint       = func(gID string) string { return fmt.Sprintf("/api/v4/groups/%s/members", gID) }
	groupMemberDetailsEndpoint = func(gID, uID string) string { return fmt.Sprintf("/api/v4/groups/%s/members/%s", gID, uID) }

	projectMembersEndpoint       = func(pID string) string { return fmt.Sprintf("/api/v4/projects/%s/members", pID) }
	projectMemberDetailsEndpoint = func(pID, uID string) string { return fmt.Sprintf("/api/v4/projects/%s/members/%s", pID, uID) }
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
		dummyGroupsBytes, err := readFixtures("testdata/groups/page_1.json")
		require.NoError(t, err)
		var dummyGroups []map[string]interface{}
		err = json.Unmarshal(dummyGroupsBytes, &dummyGroups)
		require.NoError(t, err)

		server := http.NewServeMux()
		server.HandleFunc(groupsEndpoint, func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				w.WriteHeader(http.StatusOK)
				w.Write(dummyGroupsBytes)
				return
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
				w.Write(nil)
			}
		})
		for _, g := range dummyGroups {
			gID := fmt.Sprintf("%v", g["id"])
			server.HandleFunc(groupProjectsEndpoint(gID), func(w http.ResponseWriter, r *http.Request) {
				withShared := r.URL.Query().Get("with_shared")
				switch r.Method {
				case http.MethodGet:
					assert.Equal(t, "false", withShared)
					if gID == "1" {
						projects, err := readFixtures("testdata/projects/page_1.json")
						require.NoError(t, err)
						w.WriteHeader(http.StatusOK)
						w.Write(projects)
						return
					}
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("[]"))
					return
				default:
					w.WriteHeader(http.StatusMethodNotAllowed)
					w.Write(nil)
				}
			})
		}
		ts := httptest.NewServer(server)
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
		mux := http.NewServeMux()
		mux.HandleFunc(groupsEndpoint, func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				idAfterParam := r.URL.Query().Get("id_after")
				dummyIDAfter := "999"

				var groups []byte
				var err error
				switch idAfterParam {
				case dummyIDAfter:
					groups, err = readFixtures("testdata/groups/page_2.json")
				default:
					groups, err = readFixtures("testdata/groups/page_1.json")

					q := r.URL.Query()
					q.Add("id_after", dummyIDAfter)
					r.URL.RawQuery = q.Encode()
					nextPageURL := fmt.Sprintf("http://%s/%s", r.Host, r.URL.String())
					linkHeader := fmt.Sprintf(`<%s>; rel="next"`, nextPageURL)
					w.Header().Set("Link", linkHeader)
				}
				require.NoError(t, err)

				w.WriteHeader(http.StatusOK)
				w.Write(groups)
				return
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
				w.Write(nil)
			}
		})
		ts := httptest.NewServer(mux)
		defer ts.Close()

		encryptor := new(mocks.Encryptor)
		logger := log.NewNoop()
		gitlabProvider := gitlab.NewProvider("gitlab", encryptor, logger)

		encryptor.EXPECT().Decrypt("encrypted-token").Return("test-token", nil)
		defer encryptor.AssertExpectations(t)
		expectedResourcesLen := 10 // 5 groups * 2 pages

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
		assert.Len(t, resources, expectedResourcesLen)
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
					groupMembersEndpoint("1"): func(w http.ResponseWriter, r *http.Request) {
						switch r.Method {
						case http.MethodPost:
							w.WriteHeader(http.StatusCreated)
							w.Write([]byte("{}"))
							return
						default:
							w.WriteHeader(http.StatusMethodNotAllowed)
							w.Write(nil)
						}
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
					groupMembersEndpoint("1"): func(w http.ResponseWriter, r *http.Request) {
						switch r.Method {
						case http.MethodPost:
							w.WriteHeader(http.StatusConflict)
							w.Write([]byte(`{"message": "Member already exists"}`))
							return
						default:
							w.WriteHeader(http.StatusMethodNotAllowed)
							w.Write(nil)
						}
					},
					groupMemberDetailsEndpoint("1", "99"): func(w http.ResponseWriter, r *http.Request) {
						switch r.Method {
						case http.MethodPut:
							t.Run("should reset expires_at", func(t *testing.T) {
								var reqBody map[string]any
								err := json.NewDecoder(r.Body).Decode(&reqBody)
								require.NoError(t, err)
								expAt, keyExists := reqBody["expires_at"]

								assert.True(t, keyExists)
								assert.Empty(t, expAt)
							})
							w.WriteHeader(http.StatusOK)
							w.Write([]byte("{}"))
						default:
							w.WriteHeader(http.StatusMethodNotAllowed)
							w.Write(nil)
						}
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
					projectMembersEndpoint("1"): func(w http.ResponseWriter, r *http.Request) {
						switch r.Method {
						case http.MethodPost:
							w.WriteHeader(http.StatusCreated)
							w.Write([]byte("{}"))
							return
						default:
							w.WriteHeader(http.StatusMethodNotAllowed)
							w.Write(nil)
						}
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
					projectMembersEndpoint("1"): func(w http.ResponseWriter, r *http.Request) {
						switch r.Method {
						case http.MethodPost:
							w.WriteHeader(http.StatusConflict)
							w.Write([]byte(`{"message": "Member already exists"}`))
							return
						default:
							w.WriteHeader(http.StatusMethodNotAllowed)
							w.Write(nil)
						}
					},
					projectMemberDetailsEndpoint("1", "99"): func(w http.ResponseWriter, r *http.Request) {
						switch r.Method {
						case http.MethodPut:
							t.Run("should reset expires_at", func(t *testing.T) {
								var reqBody map[string]any
								err := json.NewDecoder(r.Body).Decode(&reqBody)
								require.NoError(t, err)
								expAt, keyExists := reqBody["expires_at"]

								assert.True(t, keyExists)
								assert.Empty(t, expAt)
							})

							w.WriteHeader(http.StatusOK)
							w.Write([]byte("{}"))
							return
						default:
							w.WriteHeader(http.StatusMethodNotAllowed)
							w.Write(nil)
						}
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
					groupMemberDetailsEndpoint("1", "99"): func(w http.ResponseWriter, r *http.Request) {
						switch r.Method {
						case http.MethodGet: // check if member exists
							w.WriteHeader(http.StatusOK)
							w.Write([]byte(`{
										"access_level": 30
									}`))
							return
						case http.MethodDelete: // remove member
							t.Run("should pass skip_subresources=true", func(t *testing.T) {
								q := r.URL.Query()
								skipSubresources, keyExists := q["skip_subresources"]
								assert.True(t, keyExists)
								assert.Equal(t, []string{"true"}, skipSubresources)
							})

							w.WriteHeader(http.StatusNoContent)
							w.Write([]byte(""))
							return
						default:
							w.WriteHeader(http.StatusMethodNotAllowed)
							w.Write(nil)
						}
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
					groupMemberDetailsEndpoint("1", "99"): func(w http.ResponseWriter, r *http.Request) {
						switch r.Method {
						case http.MethodGet: // check if member exists
							w.WriteHeader(http.StatusOK)
							w.Write([]byte(`{
									"access_level": 30
								}`))
							return
						case http.MethodDelete: // remove member
							w.WriteHeader(http.StatusNotFound)
							w.Write([]byte(`{"message": "404 Not found"}`))
							return
						default:
							w.WriteHeader(http.StatusMethodNotAllowed)
							w.Write(nil)
						}
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
					projectMemberDetailsEndpoint("1", "99"): func(w http.ResponseWriter, r *http.Request) {
						switch r.Method {
						case http.MethodGet: // check if member exists
							w.WriteHeader(http.StatusOK)
							w.Write([]byte(`{
								"access_level": 30
							}`))
							return
						case http.MethodDelete: // remove member
							w.WriteHeader(http.StatusNoContent)
							w.Write([]byte(""))
							return
						default:
							w.WriteHeader(http.StatusMethodNotAllowed)
							w.Write(nil)
						}
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
					projectMemberDetailsEndpoint("1", "99"): func(w http.ResponseWriter, r *http.Request) {
						switch r.Method {
						case http.MethodGet: // check if member exists
							w.WriteHeader(http.StatusOK)
							w.Write([]byte(`{
							"access_level": 30
						}`))
							return
						case http.MethodDelete: // remove member
							w.WriteHeader(http.StatusNotFound)
							w.Write([]byte(`{"message": "404 Not found"}`))
							return
						default:
							w.WriteHeader(http.StatusMethodNotAllowed)
							w.Write(nil)
						}
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
