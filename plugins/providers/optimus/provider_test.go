package optimus_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/plugins/providers/optimus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newProvider() *optimus.Provider {
	return optimus.NewProvider("optimus", log.NewNoop())
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
	p := optimus.NewProvider("optimus", log.NewNoop())
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

		resources, err := p.GetResources(context.Background(), pc)

		require.NoError(t, err)
		require.Len(t, resources, 1)

		r := resources[0]
		assert.Equal(t, "optimus", r.ProviderType)
		assert.Equal(t, "optimus-prod", r.ProviderURN)
		assert.Equal(t, optimus.ResourceTypeJob, r.Type)
		assert.Equal(t, "my-project/my-namespace/etl-job", r.URN)
		assert.Equal(t, "etl-job", r.Name)
		assert.Equal(t, "urn:optimus:optimus-prod:job:etl-job", r.GlobalURN)
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

		_, err := p.GetResources(context.Background(), pc)
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
	assert.Equal(t, []string{"user"}, p.GetAccountTypes())
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

// ---------------------------------------------------------------------------
// IsDuplicateAppeal
// ---------------------------------------------------------------------------

func TestIsDuplicateAppeal(t *testing.T) {
	p := newProvider()
	ctx := context.Background()

	const (
		resourceID = "resource-abc"
		role       = "execute_backfill"
	)

	makeFetch := func(appeals []*domain.Appeal, err error) func(context.Context, *domain.ListAppealsFilter) ([]*domain.Appeal, error) {
		return func(_ context.Context, _ *domain.ListAppealsFilter) ([]*domain.Appeal, error) {
			return appeals, err
		}
	}

	incoming := appealWithParams("appeal-new", resourceID, role, map[string]interface{}{
		"start_time": "2024-02-01T00:00:00Z",
		"end_time":   "2024-02-10T00:00:00Z",
	})

	tests := []struct {
		name      string
		incoming  *domain.Appeal
		fetch     func(context.Context, *domain.ListAppealsFilter) ([]*domain.Appeal, error)
		wantDup   bool
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "fetchPending returns error",
			incoming:  incoming,
			fetch:     makeFetch(nil, errors.New("db error")),
			wantErr:   true,
			errSubstr: "fetching pending appeals",
		},
		{
			name:    "no existing appeals → not a duplicate",
			incoming: incoming,
			fetch:   makeFetch(nil, nil),
			wantDup: false,
		},
		{
			name:    "self excluded by ID → not a duplicate",
			incoming: incoming,
			fetch: makeFetch([]*domain.Appeal{
				appealWithParams("appeal-new", resourceID, role, map[string]interface{}{
					"start_time": "2024-02-01T00:00:00Z",
					"end_time":   "2024-02-10T00:00:00Z",
				}),
			}, nil),
			wantDup: false,
		},
		{
			name:    "overlapping window → duplicate",
			incoming: incoming,
			fetch: makeFetch([]*domain.Appeal{
				appealWithParams("appeal-existing", resourceID, role, map[string]interface{}{
					"start_time": "2024-02-05T00:00:00Z",
					"end_time":   "2024-02-15T00:00:00Z",
				}),
			}, nil),
			wantDup: true,
		},
		{
			name:    "existing window fully inside incoming → duplicate",
			incoming: incoming,
			fetch: makeFetch([]*domain.Appeal{
				appealWithParams("appeal-existing", resourceID, role, map[string]interface{}{
					"start_time": "2024-02-03T00:00:00Z",
					"end_time":   "2024-02-07T00:00:00Z",
				}),
			}, nil),
			wantDup: true,
		},
		{
			name:    "incoming fully before existing → not a duplicate",
			incoming: incoming,
			fetch: makeFetch([]*domain.Appeal{
				appealWithParams("appeal-existing", resourceID, role, map[string]interface{}{
					"start_time": "2024-03-01T00:00:00Z",
					"end_time":   "2024-03-10T00:00:00Z",
				}),
			}, nil),
			wantDup: false,
		},
		{
			name:    "incoming fully after existing → not a duplicate",
			incoming: incoming,
			fetch: makeFetch([]*domain.Appeal{
				appealWithParams("appeal-existing", resourceID, role, map[string]interface{}{
					"start_time": "2024-01-01T00:00:00Z",
					"end_time":   "2024-01-15T00:00:00Z",
				}),
			}, nil),
			wantDup: false,
		},
		{
			name:    "adjacent windows (incoming end == existing start) → duplicate",
			incoming: incoming,
			fetch: makeFetch([]*domain.Appeal{
				appealWithParams("appeal-existing", resourceID, role, map[string]interface{}{
					"start_time": "2024-02-10T00:00:00Z",
					"end_time":   "2024-02-20T00:00:00Z",
				}),
			}, nil),
			wantDup: true,
		},
		{
			name:    "one non-overlapping and one overlapping → duplicate",
			incoming: incoming,
			fetch: makeFetch([]*domain.Appeal{
				appealWithParams("appeal-before", resourceID, role, map[string]interface{}{
					"start_time": "2024-01-01T00:00:00Z",
					"end_time":   "2024-01-15T00:00:00Z",
				}),
				appealWithParams("appeal-overlap", resourceID, role, map[string]interface{}{
					"start_time": "2024-02-05T00:00:00Z",
					"end_time":   "2024-02-15T00:00:00Z",
				}),
			}, nil),
			wantDup: true,
		},
		{
			name:    "existing appeal missing __provider_parameters → error",
			incoming: incoming,
			fetch: makeFetch([]*domain.Appeal{
				{ID: "bad-appeal", Details: map[string]interface{}{}},
			}, nil),
			wantErr:   true,
			errSubstr: "reading existing appeal parameters",
		},
		{
			name:    "existing appeal has invalid start_time → error",
			incoming: incoming,
			fetch: makeFetch([]*domain.Appeal{
				appealWithParams("bad-appeal", resourceID, role, map[string]interface{}{
					"start_time": "not-a-date",
					"end_time":   "2024-02-15T00:00:00Z",
				}),
			}, nil),
			wantErr:   true,
			errSubstr: "parsing existing start_time",
		},
		{
			name:    "existing appeal has invalid end_time → error",
			incoming: incoming,
			fetch: makeFetch([]*domain.Appeal{
				appealWithParams("bad-appeal", resourceID, role, map[string]interface{}{
					"start_time": "2024-02-05T00:00:00Z",
					"end_time":   "not-a-date",
				}),
			}, nil),
			wantErr:   true,
			errSubstr: "parsing existing end_time",
		},
		{
			name: "incoming appeal missing __provider_parameters → error",
			incoming: &domain.Appeal{
				ID:         "new-appeal",
				ResourceID: resourceID,
				Role:       role,
				Details:    map[string]interface{}{},
			},
			fetch:     makeFetch(nil, nil),
			wantErr:   true,
			errSubstr: "reading incoming appeal parameters",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isDup, err := p.IsDuplicateAppeal(ctx, tc.incoming, tc.fetch)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errSubstr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.wantDup, isDup)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// fetchPending filter passthrough
// ---------------------------------------------------------------------------

func TestIsDuplicateAppeal_FetchCalledWithCorrectFilter(t *testing.T) {
	p := newProvider()
	ctx := context.Background()

	incoming := appealWithParams("new-appeal", "resource-xyz", "execute_backfill", map[string]interface{}{
		"start_time": "2024-05-01T00:00:00Z",
		"end_time":   "2024-05-10T00:00:00Z",
	})

	var capturedFilter *domain.ListAppealsFilter
	fetch := func(_ context.Context, f *domain.ListAppealsFilter) ([]*domain.Appeal, error) {
		capturedFilter = f
		return nil, nil
	}

	_, err := p.IsDuplicateAppeal(ctx, incoming, fetch)
	require.NoError(t, err)

	require.NotNil(t, capturedFilter)
	assert.Equal(t, []string{"resource-xyz"}, capturedFilter.ResourceIDs)
	assert.Equal(t, []string{"execute_backfill"}, capturedFilter.Roles)
	assert.Equal(t, []string{domain.AppealStatusPending}, capturedFilter.Statuses)
}

// ---------------------------------------------------------------------------
// IsDuplicateAppeal — invalid incoming start_time (fetched appeals irrelevant)
// ---------------------------------------------------------------------------

func TestIsDuplicateAppeal_InvalidIncomingStartTime(t *testing.T) {
	p := newProvider()

	incoming := appealWithParams("x", "r", "role", map[string]interface{}{
		"start_time": "bad",
		"end_time":   "2024-01-10T00:00:00Z",
	})

	fetch := func(_ context.Context, _ *domain.ListAppealsFilter) ([]*domain.Appeal, error) {
		return nil, nil
	}

	_, err := p.IsDuplicateAppeal(context.Background(), incoming, fetch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing incoming start_time")
}

func TestIsDuplicateAppeal_InvalidIncomingEndTime(t *testing.T) {
	p := newProvider()

	incoming := appealWithParams("x", "r", "role", map[string]interface{}{
		"start_time": "2024-01-01T00:00:00Z",
		"end_time":   "bad",
	})

	fetch := func(_ context.Context, _ *domain.ListAppealsFilter) ([]*domain.Appeal, error) {
		return nil, nil
	}

	_, err := p.IsDuplicateAppeal(context.Background(), incoming, fetch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("parsing incoming end_time"))
}
