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
				err := tc.grantUpdate.Validate()
				if tc.expectedErrorMsg != "" {
					assert.ErrorContains(t, err, tc.expectedErrorMsg)
				} else {
					assert.Nil(t, err)
				}
			})
		}
	})

	t.Run("update expiration date", func(t *testing.T) {
		trueBoolean := true
		falseBoolean := false
		yesterday := time.Now().Add(-24 * time.Hour)
		tomorrow := time.Now().Add(24 * time.Hour)
		reason := "test reason"
		emptyString := ""
		testCases := []struct {
			name             string
			grantUpdate      *domain.GrantUpdate
			expectedErrorMsg string
		}{
			// success scenarios
			{
				name: "update to permanent",
				grantUpdate: &domain.GrantUpdate{
					IsPermanent:          &trueBoolean,
					ExpirationDateReason: &reason,
				},
			},
			{
				name: "update to non-permanent",
				grantUpdate: &domain.GrantUpdate{
					ExpirationDate:       &tomorrow,
					ExpirationDateReason: &reason,
				},
			},
			{
				name: "update to non-permanent with explicit is_permanent=false",
				grantUpdate: &domain.GrantUpdate{
					IsPermanent:          &falseBoolean,
					ExpirationDate:       &tomorrow,
					ExpirationDateReason: &reason,
				},
			},

			// failed scenarios
			{
				name: "update to permanent should not specify expiration_date",
				grantUpdate: &domain.GrantUpdate{
					IsPermanent:          &trueBoolean,
					ExpirationDate:       &tomorrow, // unexpectedd
					ExpirationDateReason: &reason,
				},
				expectedErrorMsg: "expiration date should be nil for updating grant to permanent",
			},
			{
				name: "update to permanent without reason should break",
				grantUpdate: &domain.GrantUpdate{
					IsPermanent: &trueBoolean,
				},
				expectedErrorMsg: "expiration date reason is required",
			},
			{
				name: "update to permanent with empty reason should break",
				grantUpdate: &domain.GrantUpdate{
					IsPermanent:          &trueBoolean,
					ExpirationDateReason: &emptyString,
				},
				expectedErrorMsg: "expiration date reason is required",
			},
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
				name: "update to non-permanent with is_permanent=false without expiration_date should break",
				grantUpdate: &domain.GrantUpdate{
					IsPermanent: &falseBoolean,
				},
				expectedErrorMsg: "expiration date is required",
			},
			{
				name: "specify reason without is_permanent and expiration_date specified should break",
				grantUpdate: &domain.GrantUpdate{
					ExpirationDateReason: &reason,
				},
				expectedErrorMsg: "expiration date is required",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				tc.grantUpdate.ID = "test-id"
				err := tc.grantUpdate.Validate()
				if tc.expectedErrorMsg != "" {
					assert.ErrorContains(t, err, tc.expectedErrorMsg)
				} else {
					assert.Nil(t, err)
				}
			})
		}
	})
}
