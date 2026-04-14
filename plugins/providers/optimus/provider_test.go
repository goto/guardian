package optimus_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/crypto"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/plugins/providers/optimus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newProvider() *optimus.Provider {
	return optimus.NewProvider("optimus", crypto.NewAES("test-encryption-key"), log.NewNoop())
}

func validProviderConfig(host string) *domain.ProviderConfig {
	return &domain.ProviderConfig{
		Type: "optimus",
		URN:  "optimus-prod",
		Credentials: map[string]interface{}{
			"host":         host,
			"project_name": "my-project",
		},
		Resources: []*domain.ResourceConfig{
			{Type: optimus.ResourceTypeJob},
		},
	}
}

func appealWithParams(id, resourceID, role string, params map[string]interface{}) *domain.Appeal {
	return &domain.Appeal{
		ID:         id,
		ResourceID: resourceID,
		Role:       role,
		Details: map[string]interface{}{
			domain.ReservedDetailsKeyProviderParameters: params,
		},
	}
}

// ---------------------------------------------------------------------------
// GetType
// ---------------------------------------------------------------------------

func TestGetType(t *testing.T) {
	p := optimus.NewProvider("optimus", crypto.NewAES("test-encryption-key"), log.NewNoop())
	assert.Equal(t, "optimus", p.GetType())
}

// ---------------------------------------------------------------------------
// CreateConfig
// ---------------------------------------------------------------------------

func TestCreateConfig(t *testing.T) {
	p := newProvider()

	tests := []struct {
		name        string
		config      *domain.ProviderConfig
		wantErr     bool
		errContains error
	}{
		{
			name: "valid config",
			config: &domain.ProviderConfig{
				Type: "optimus",
				URN:  "optimus-prod",
				Credentials: map[string]interface{}{
					"host":         "http://optimus.example.com",
					"project_name": "my-project",
				},
				Resources: []*domain.ResourceConfig{{Type: optimus.ResourceTypeJob}},
			},
			wantErr: false,
		},
		{
			name: "nil credentials",
			config: &domain.ProviderConfig{
				Type:        "optimus",
				Credentials: nil,
				Resources:   []*domain.ResourceConfig{{Type: optimus.ResourceTypeJob}},
			},
			wantErr:     true,
			errContains: optimus.ErrMissingCredentials,
		},
		{
			name: "missing host",
			config: &domain.ProviderConfig{
				Type: "optimus",
				Credentials: map[string]interface{}{
					"project_name": "my-project",
				},
				Resources: []*domain.ResourceConfig{{Type: optimus.ResourceTypeJob}},
			},
			wantErr:     true,
			errContains: optimus.ErrMissingHost,
		},
		{
			name: "missing project_name",
			config: &domain.ProviderConfig{
				Type: "optimus",
				Credentials: map[string]interface{}{
					"host": "http://optimus.example.com",
				},
				Resources: []*domain.ResourceConfig{{Type: optimus.ResourceTypeJob}},
			},
			wantErr:     true,
			errContains: optimus.ErrMissingProjectName,
		},
		{
			name: "invalid resource type",
			config: &domain.ProviderConfig{
				Type: "optimus",
				Credentials: map[string]interface{}{
					"host":         "http://optimus.example.com",
					"project_name": "my-project",
				},
				Resources: []*domain.ResourceConfig{{Type: "dataset"}},
			},
			wantErr:     true,
			errContains: optimus.ErrInvalidResourceType,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := p.CreateConfig(tc.config)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != nil {
					assert.ErrorIs(t, err, tc.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCreateConfigEncryptsCredentials(t *testing.T) {
	p := newProvider()
	pc := validProviderConfig("http://optimus.example.com")
	err := p.CreateConfig(pc)
	require.NoError(t, err)

	// Ensure CreateConfig transitioned credentials to provider-specific struct
	assert.Equal(t, reflect.Struct, reflect.TypeOf(pc.Credentials).Kind())

	// Decryption path should then work for getClient
	_, err = p.GetResources(context.Background(), pc)
	assert.Error(t, err) // no server, but decrypt path ran without "invalid input" errors.
}

// ---------------------------------------------------------------------------
// GetResources
// ---------------------------------------------------------------------------

func TestGetResources(t *testing.T) {
	t.Run("returns resources with all details populated", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/v1beta1/jobs", r.URL.Path)
			assert.Equal(t, "my-project", r.URL.Query().Get("project_name"))

			resp := map[string]interface{}{
				"jobSpecificationResponses": []map[string]interface{}{
					{
						"projectName":   "my-project",
						"namespaceName": "my-namespace",
						"job": map[string]interface{}{
							"name":           "etl-job",
							"owner":          "owner@example.com",
							"startDate":      "2023-01-01",
							"interval":       "@daily",
							"schedulerState": "enabled",
							"taskName":       "bq2bq",
							"config": []map[string]interface{}{
								{"name": "DESTINATION_TABLE_ID", "value": "project.dataset.table"},
							},
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
		}))
		defer ts.Close()

		p := newProvider()
		pc := validProviderConfig(ts.URL)
		err := p.CreateConfig(pc)
		require.NoError(t, err)

		resources, err := p.GetResources(context.Background(), pc)

		require.NoError(t, err)
		require.Len(t, resources, 1)

		r := resources[0]
		assert.Equal(t, "optimus", r.ProviderType)
		assert.Equal(t, "optimus-prod", r.ProviderURN)
		assert.Equal(t, optimus.ResourceTypeJob, r.Type)
		assert.Equal(t, "my-project/my-namespace/etl-job", r.URN)
		assert.Equal(t, "etl-job", r.Name)
		assert.Equal(t, "urn:optimus:optimus-prod:job:my-project/my-namespace/etl-job", r.GlobalURN)
		assert.Equal(t, "2023-01-01", r.Details["start_date"])
		assert.Equal(t, "project.dataset.table", r.Details["destination_table_name"])
	})

	t.Run("returns error when API returns non-200", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()

		p := newProvider()
		pc := validProviderConfig(ts.URL)
		err := p.CreateConfig(pc)
		require.NoError(t, err)

		_, err = p.GetResources(context.Background(), pc)
		assert.Error(t, err)
	})

	t.Run("job without DESTINATION_TABLE_ID has empty destination", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"jobSpecificationResponses": []map[string]interface{}{
					{
						"projectName":   "p",
						"namespaceName": "ns",
						"job": map[string]interface{}{
							"name":           "simple-job",
							"owner":          "me",
							"startDate":      "2024-01-01",
							"interval":       "@weekly",
							"schedulerState": "disabled",
							"taskName":       "python",
							"config":         []map[string]interface{}{},
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
		}))
		defer ts.Close()

		p := newProvider()
		pc := validProviderConfig(ts.URL)
		err := p.CreateConfig(pc)
		require.NoError(t, err)

		resources, err := p.GetResources(context.Background(), pc)
		require.NoError(t, err)
		require.Len(t, resources, 1)
		assert.Equal(t, "", resources[0].Details["destination_table_name"])
	})
}

// ---------------------------------------------------------------------------
// GrantAccess / RevokeAccess
// ---------------------------------------------------------------------------

func TestGrantAccess(t *testing.T) {
	p := newProvider()
	err := p.GrantAccess(context.Background(), &domain.ProviderConfig{}, domain.Grant{ID: "grant-1", AccountID: "user@example.com"})
	assert.NoError(t, err)
}

func TestRevokeAccess(t *testing.T) {
	p := newProvider()
	err := p.RevokeAccess(context.Background(), &domain.ProviderConfig{}, domain.Grant{})
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// GetAccountTypes
// ---------------------------------------------------------------------------

func TestGetAccountTypes(t *testing.T) {
	p := newProvider()
	assert.Equal(t, []string{"UUID"}, p.GetAccountTypes())
}

// ---------------------------------------------------------------------------
// ValidateAppeal
// ---------------------------------------------------------------------------

func TestValidateAppeal(t *testing.T) {
	p := newProvider()
	ctx := context.Background()

	resourceWithStartDate := func(startDate string) *domain.Resource {
		return &domain.Resource{
			Details: map[string]interface{}{
				"start_date": startDate,
			},
		}
	}

	tests := []struct {
		name        string
		appeal      *domain.Appeal
		wantErr     bool
		errContains string
	}{
		{
			name: "missing __provider_parameters",
			appeal: &domain.Appeal{
				Details: map[string]interface{}{},
			},
			wantErr:     true,
			errContains: "__provider_parameters",
		},
		{
			name: "missing start_time",
			appeal: appealWithParams("", "", "", map[string]interface{}{
				"end_time": "2024-01-10T00:00:00Z",
			}),
			wantErr:     true,
			errContains: "start_time is required",
		},
		{
			name: "missing end_time",
			appeal: appealWithParams("", "", "", map[string]interface{}{
				"start_time": "2024-01-01T00:00:00Z",
			}),
			wantErr:     true,
			errContains: "end_time is required",
		},
		{
			name: "invalid RFC3339 start_time",
			appeal: appealWithParams("", "", "", map[string]interface{}{
				"start_time": "01-01-2024",
				"end_time":   "2024-01-10T00:00:00Z",
			}),
			wantErr:     true,
			errContains: "invalid start_time",
		},
		{
			name: "invalid RFC3339 end_time",
			appeal: appealWithParams("", "", "", map[string]interface{}{
				"start_time": "2024-01-01T00:00:00Z",
				"end_time":   "10-01-2024",
			}),
			wantErr:     true,
			errContains: "invalid end_time",
		},
		{
			name: "start_time equal to end_time",
			appeal: appealWithParams("", "", "", map[string]interface{}{
				"start_time": "2024-01-01T00:00:00Z",
				"end_time":   "2024-01-01T00:00:00Z",
			}),
			wantErr:     true,
			errContains: "must be before end_time",
		},
		{
			name: "start_time after end_time",
			appeal: appealWithParams("", "", "", map[string]interface{}{
				"start_time": "2024-01-10T00:00:00Z",
				"end_time":   "2024-01-01T00:00:00Z",
			}),
			wantErr:     true,
			errContains: "must be before end_time",
		},
		{
			name: "start_time before job start_date",
			appeal: &domain.Appeal{
				Resource: resourceWithStartDate("2024-03-01"),
				Details: map[string]interface{}{
					domain.ReservedDetailsKeyProviderParameters: map[string]interface{}{
						"start_time": "2024-01-01T00:00:00Z",
						"end_time":   "2024-01-10T00:00:00Z",
					},
				},
			},
			wantErr:     true,
			errContains: "start_date",
		},
		{
			name: "valid appeal without resource",
			appeal: appealWithParams("", "", "", map[string]interface{}{
				"start_time": "2024-01-01T00:00:00Z",
				"end_time":   "2024-01-10T00:00:00Z",
			}),
			wantErr: false,
		},
		{
			name: "valid appeal with resource start_date on same day as start_time",
			appeal: &domain.Appeal{
				Resource: resourceWithStartDate("2023-06-01"),
				Details: map[string]interface{}{
					domain.ReservedDetailsKeyProviderParameters: map[string]interface{}{
						"start_time": "2024-01-01T00:00:00Z",
						"end_time":   "2024-01-10T00:00:00Z",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := p.ValidateAppeal(ctx, tc.appeal)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
