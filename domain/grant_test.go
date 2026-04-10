package domain_test

import (
	"testing"
	"time"

	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/assert"
)

func TestGrantUpdate_Validate(t *testing.T) {
	t.Run("update owner", func(t *testing.T) {
		owner := "test-owner"
		emptyString := ""
		testCases := []struct {
			name             string
			currentGrant     domain.Grant
			grantUpdate      *domain.GrantUpdate
			expectedErrorMsg string
		}{
			{
				name: "update owner",
				currentGrant: domain.Grant{
					Status: domain.GrantStatusActive,
				},
				grantUpdate: &domain.GrantUpdate{
					Owner: &owner,
				},
			},
			{
				name: "update owner to empty should break",
				currentGrant: domain.Grant{
					Status: domain.GrantStatusActive,
				},
				grantUpdate: &domain.GrantUpdate{
					Owner: &emptyString,
				},
				expectedErrorMsg: "owner should not be empty",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				tc.grantUpdate.ID = "test-id"
				err := tc.grantUpdate.Validate(tc.currentGrant)
				if tc.expectedErrorMsg != "" {
					assert.ErrorContains(t, err, tc.expectedErrorMsg)
				} else {
					assert.Nil(t, err)
				}
			})
		}
	})

	t.Run("update expiration date", func(t *testing.T) {
		yesterday := time.Now().Add(-24 * time.Hour)
		tomorrow := time.Now().Add(24 * time.Hour)
		afterTomorrow := time.Now().Add(48 * time.Hour)
		reason := "test reason"
		emptyString := ""
		testCases := []struct {
			name             string
			currentGrant     domain.Grant
			grantUpdate      *domain.GrantUpdate
			expectedErrorMsg string
		}{
			// success scenarios
			{
				name: "reduce expiration date",
				currentGrant: domain.Grant{
					Status:         domain.GrantStatusActive,
					ExpirationDate: &afterTomorrow,
				},
				grantUpdate: &domain.GrantUpdate{
					ExpirationDate:       &tomorrow,
					ExpirationDateReason: &reason,
				},
			},
			{
				name: "update permanent grant to non-permanent",
				currentGrant: domain.Grant{
					Status:      domain.GrantStatusActive,
					IsPermanent: true,
				},
				grantUpdate: &domain.GrantUpdate{
					ExpirationDate:       &tomorrow,
					ExpirationDateReason: &reason,
				},
			},

			// failed scenarios
			{
				name: "current grant is already inactive",
				currentGrant: domain.Grant{
					Status: domain.GrantStatusInactive,
				},
				grantUpdate: &domain.GrantUpdate{
					ExpirationDate:       &tomorrow,
					ExpirationDateReason: &reason,
				},
				expectedErrorMsg: `can't update grant in status "inactive"`,
			},
			{
				name: "update to non-permanent; expiration date should not be in the past",
				currentGrant: domain.Grant{
					Status: domain.GrantStatusActive,
				},
				grantUpdate: &domain.GrantUpdate{
					ExpirationDate:       &yesterday,
					ExpirationDateReason: &reason,
				},
				expectedErrorMsg: "expiration date can't be in the past",
			},
			{
				name: "update to non-permanent without reason should break",
				currentGrant: domain.Grant{
					Status: domain.GrantStatusActive,
				},
				grantUpdate: &domain.GrantUpdate{
					ExpirationDate: &tomorrow,
				},
				expectedErrorMsg: "expiration date reason is required",
			},
			{
				name: "update to non-permanent with empty reason should break",
				currentGrant: domain.Grant{
					Status: domain.GrantStatusActive,
				},
				grantUpdate: &domain.GrantUpdate{
					ExpirationDate:       &tomorrow,
					ExpirationDateReason: &emptyString,
				},
				expectedErrorMsg: "expiration date reason is required",
			},
			{
				name: "specify reason without is_permanent and expiration_date specified should break",
				currentGrant: domain.Grant{
					Status: domain.GrantStatusActive,
				},
				grantUpdate: &domain.GrantUpdate{
					ExpirationDateReason: &reason,
				},
				expectedErrorMsg: "expiration date is required",
			},
			{
				name: "new exp date more than current exp date",
				currentGrant: domain.Grant{
					Status:         domain.GrantStatusActive,
					ExpirationDate: &tomorrow,
				},
				grantUpdate: &domain.GrantUpdate{
					ExpirationDate:       &afterTomorrow,
					ExpirationDateReason: &reason,
				},
				expectedErrorMsg: "expiration date should be less than existing",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				tc.grantUpdate.ID = "test-id"
				err := tc.grantUpdate.Validate(tc.currentGrant)
				if tc.expectedErrorMsg != "" {
					assert.ErrorContains(t, err, tc.expectedErrorMsg)
				} else {
					assert.Nil(t, err)
				}
			})
		}
	})
}

func TestGrant_PermissionsKey(t *testing.T) {
	g := domain.Grant{Permissions: []string{"write", "admin", "read"}}
	assert.Equal(t, "admin;read;write", g.PermissionsKey())

	empty := domain.Grant{}
	assert.Equal(t, "", empty.PermissionsKey())
}

func TestGrant_IsEligibleForExtension(t *testing.T) {
	future := time.Now().Add(2 * time.Hour)
	past := time.Now().Add(-1 * time.Hour)

	t.Run("permanent grant is always eligible", func(t *testing.T) {
		g := domain.Grant{IsPermanent: true}
		assert.True(t, g.IsEligibleForExtension(24*time.Hour))
	})
	t.Run("no expiration date is eligible", func(t *testing.T) {
		g := domain.Grant{}
		assert.True(t, g.IsEligibleForExtension(24*time.Hour))
	})
	t.Run("expiration within rule duration is eligible", func(t *testing.T) {
		g := domain.Grant{ExpirationDate: &future}
		assert.True(t, g.IsEligibleForExtension(24*time.Hour))
	})
	t.Run("expiration far in future is not eligible", func(t *testing.T) {
		g := domain.Grant{ExpirationDate: &future}
		assert.False(t, g.IsEligibleForExtension(1*time.Minute))
	})
	t.Run("already expired is eligible", func(t *testing.T) {
		g := domain.Grant{ExpirationDate: &past}
		assert.True(t, g.IsEligibleForExtension(1*time.Hour))
	})
}

func TestGrant_Revoke(t *testing.T) {
	t.Run("revokes successfully", func(t *testing.T) {
		g := &domain.Grant{Status: domain.GrantStatusActive}
		err := g.Revoke("admin@example.com", "no longer needed")
		assert.NoError(t, err)
		assert.Equal(t, domain.GrantStatusInactive, g.Status)
		assert.Equal(t, "admin@example.com", g.RevokedBy)
		assert.Equal(t, "no longer needed", g.RevokeReason)
		assert.NotNil(t, g.RevokedAt)
	})
	t.Run("returns error for empty actor", func(t *testing.T) {
		g := &domain.Grant{}
		err := g.Revoke("", "reason")
		assert.Error(t, err)
	})
}

func TestGrant_Restore(t *testing.T) {
	future := time.Now().Add(24 * time.Hour)
	past := time.Now().Add(-24 * time.Hour)

	t.Run("restores successfully", func(t *testing.T) {
		g := &domain.Grant{Status: domain.GrantStatusInactive, IsPermanent: true}
		err := g.Restore("admin@example.com", "reinstated")
		assert.NoError(t, err)
		assert.Equal(t, domain.GrantStatusActive, g.Status)
		assert.Equal(t, "admin@example.com", g.RestoredBy)
		assert.Equal(t, "reinstated", g.RestoreReason)
	})
	t.Run("returns error for empty actor", func(t *testing.T) {
		g := &domain.Grant{IsPermanent: true}
		err := g.Restore("", "reason")
		assert.Error(t, err)
	})
	t.Run("returns error for empty reason", func(t *testing.T) {
		g := &domain.Grant{IsPermanent: true}
		err := g.Restore("admin@example.com", "")
		assert.Error(t, err)
	})
	t.Run("returns error when grant is expired", func(t *testing.T) {
		g := &domain.Grant{ExpirationDate: &past}
		err := g.Restore("admin@example.com", "reinstated")
		assert.Error(t, err)
	})
	t.Run("non-permanent with future expiration restores successfully", func(t *testing.T) {
		g := &domain.Grant{ExpirationDate: &future}
		err := g.Restore("admin@example.com", "reinstated")
		assert.NoError(t, err)
	})
}

func TestGrant_GetPermissions(t *testing.T) {
	g := &domain.Grant{Permissions: []string{"read", "write"}}
	assert.Equal(t, []string{"read", "write"}, g.GetPermissions())

	empty := &domain.Grant{}
	assert.Nil(t, empty.GetPermissions())
}

func TestListGrantsFilter_WithSummary(t *testing.T) {
	assert.False(t, domain.ListGrantsFilter{}.WithSummary())
	assert.True(t, domain.ListGrantsFilter{SummaryGroupBys: []string{"status"}}.WithSummary())
	assert.True(t, domain.ListGrantsFilter{SummaryLabels: true}.WithSummary())
	assert.True(t, domain.ListGrantsFilter{SummaryLabelsV2: true}.WithSummary())
}

func TestListGrantsFilter_WithGrants(t *testing.T) {
	assert.True(t, domain.ListGrantsFilter{}.WithGrants())
	assert.False(t, domain.ListGrantsFilter{FieldMasks: []string{"grants"}}.WithGrants())
}

func TestListGrantsFilter_WithTotal(t *testing.T) {
	assert.True(t, domain.ListGrantsFilter{}.WithTotal())
	assert.False(t, domain.ListGrantsFilter{FieldMasks: []string{"total"}}.WithTotal())
}

func TestAccessEntry_ToGrant(t *testing.T) {
	resource := domain.Resource{ID: "res-1"}

	t.Run("user account sets owner", func(t *testing.T) {
		ae := domain.AccessEntry{AccountID: "user@example.com", AccountType: "user", Permission: "viewer"}
		g := ae.ToGrant(resource)
		assert.Equal(t, "res-1", g.ResourceID)
		assert.Equal(t, "user@example.com", g.Owner)
		assert.Equal(t, domain.GrantStatusActive, g.Status)
		assert.True(t, g.IsPermanent)
	})
	t.Run("service account does not set owner", func(t *testing.T) {
		ae := domain.AccessEntry{AccountID: "svc@project.iam.gserviceaccount.com", AccountType: "serviceAccount", Permission: "editor"}
		g := ae.ToGrant(resource)
		assert.Equal(t, "", g.Owner)
		assert.Equal(t, "editor", g.Role)
	})
}
