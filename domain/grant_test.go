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
				grantUpdate: &domain.GrantUpdate{
					Owner: &owner,
				},
			},
			{
				name: "update owner to empty should break",
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
					IsPermanent: true,
				},
				grantUpdate: &domain.GrantUpdate{
					ExpirationDate:       &tomorrow,
					ExpirationDateReason: &reason,
				},
			},

			// failed scenarios
			{
				name: "update to non-permanent; expiration date should not be in the past",
				grantUpdate: &domain.GrantUpdate{
					ExpirationDate:       &yesterday,
					ExpirationDateReason: &reason,
				},
				expectedErrorMsg: "expiration date can't be in the past",
			},
			{
				name: "update to non-permanent without reason should break",
				grantUpdate: &domain.GrantUpdate{
					ExpirationDate: &tomorrow,
				},
				expectedErrorMsg: "expiration date reason is required",
			},
			{
				name: "update to non-permanent with empty reason should break",
				grantUpdate: &domain.GrantUpdate{
					ExpirationDate:       &tomorrow,
					ExpirationDateReason: &emptyString,
				},
				expectedErrorMsg: "expiration date reason is required",
			},
			{
				name: "specify reason without is_permanent and expiration_date specified should break",
				grantUpdate: &domain.GrantUpdate{
					ExpirationDateReason: &reason,
				},
				expectedErrorMsg: "expiration date is required",
			},
			{
				name: "new exp date more than current exp date",
				currentGrant: domain.Grant{
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
