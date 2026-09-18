package maxcompute

import (
	"errors"
	"testing"

	"github.com/goto/guardian/domain"
)

func TestMatchMissingPrincipalError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		err       error
		wantOK    bool
		wantStale string
	}{
		{
			name:      "v4 user does not exist",
			err:       errors.New("fail to grant project role to 'p_mgmc_id_data_access': the user v4_301063152281913113 does not exist"),
			wantOK:    true,
			wantStale: "v4_301063152281913113",
		},
		{
			name:   "principal RAM role does not exist",
			err:    errors.New("fail to grant table role to 'haryo_poc_playground.default.v_cross_from_mart': Principal 'RAM$5866780647397444:role/aliyunreservedsso-fullreadonlyaccess' does not exist in the project"),
			wantOK: true,
		},
		{
			name:   "unrelated error",
			err:    errors.New("fail to grant project role: ObjectAlreadyExists"),
			wantOK: false,
		},
		{
			name:   "nil error",
			err:    nil,
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			info, ok := MatchMissingPrincipalError(tt.err)
			if ok != tt.wantOK {
				t.Fatalf("ok=%v want %v", ok, tt.wantOK)
			}
			if info.StaleUser != tt.wantStale {
				t.Fatalf("StaleUser=%q want %q", info.StaleUser, tt.wantStale)
			}
		})
	}
}

func TestProjectNameFromResource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		resource *domain.Resource
		want     string
		wantOK   bool
	}{
		{
			name: "project",
			resource: &domain.Resource{
				ProviderType: sourceName,
				Type:         resourceTypeProject,
				URN:          "p_mgmc_id_data_access",
			},
			want:   "p_mgmc_id_data_access",
			wantOK: true,
		},
		{
			name: "table",
			resource: &domain.Resource{
				ProviderType: sourceName,
				Type:         resourceTypeTable,
				URN:          "p_mgmc_id_mart.library.books",
			},
			want:   "p_mgmc_id_mart",
			wantOK: true,
		},
		{
			name: "schema",
			resource: &domain.Resource{
				ProviderType: sourceName,
				Type:         resourceTypeSchema,
				URN:          "p_mgmc_id_mart.library",
			},
			want:   "p_mgmc_id_mart",
			wantOK: true,
		},
		{
			name: "wrong provider",
			resource: &domain.Resource{
				ProviderType: "oss",
				Type:         resourceTypeProject,
				URN:          "bucket",
			},
			wantOK: false,
		},
		{
			name: "empty project urn",
			resource: &domain.Resource{
				ProviderType: sourceName,
				Type:         resourceTypeProject,
				URN:          "",
			},
			wantOK: false,
		},
		{
			name:   "nil resource",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := ProjectNameFromResource(tt.resource)
			if ok != tt.wantOK {
				t.Fatalf("ok=%v want %v (got %q)", ok, tt.wantOK, got)
			}
			if got != tt.want {
				t.Fatalf("project=%q want %q", got, tt.want)
			}
		})
	}
}
