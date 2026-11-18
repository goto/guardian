package appeal

import (
	"testing"
	"time"

	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/require"
)

func TestExtensionConflictUsesTheMatchingGrantAndPolicyWindow(t *testing.T) {
	service := &Service{}
	expiresAt := time.Now().UTC().Add(20 * 24 * time.Hour)
	request := &domain.Appeal{
		AccountType: "ram_role",
		GroupID:     "test-package",
		GroupType:   "package_access",
		ResourceID:  "test-schema",
		Resource:    &domain.Resource{ProviderType: "maxcompute", URN: "example_project.archive"},
	}
	grant := &domain.Grant{
		AccountType:    "ram_role",
		GroupID:        "test-package",
		GroupType:      "package_access",
		AppealID:       "active-appeal",
		ExpirationDate: &expiresAt,
	}
	provider := &domain.Provider{
		Config: &domain.ProviderConfig{
			Appeal: &domain.AppealConfig{AllowActiveAccessExtensionIn: "480h"},
		},
	}
	policy := &domain.Policy{
		AppealConfig: &domain.PolicyAppealConfig{AllowActiveAccessExtensionIn: "336h"},
	}

	err := service.checkExtensionEligibility(request, provider, policy, grant)
	require.ErrorIs(t, err, ErrGrantNotEligibleForExtension)
	var conflict *ActiveGrantConflict
	require.ErrorAs(t, err, &conflict)
	require.Equal(t, "active-appeal", conflict.AppealID)
	require.Equal(t, "example_project.archive", conflict.ResourceName)
	require.Equal(t, &expiresAt, conflict.ExpiresAt)
	require.Equal(t, "336h", conflict.RenewalWindow)
	require.Equal(t, expiresAt.Add(-336*time.Hour), *conflict.RenewalEligibleAt)

	grant.GroupID = "other-package"
	err = service.checkExtensionEligibility(request, provider, policy, grant)
	require.ErrorIs(t, err, ErrGrantNotEligibleForExtension)
	require.ErrorAs(t, err, &conflict)
	require.Empty(t, conflict.AppealID)
	require.Nil(t, conflict.ExpiresAt)
	require.Nil(t, conflict.RenewalEligibleAt)

	require.NoError(t, service.checkExtensionEligibility(request, provider, nil, grant))
}
