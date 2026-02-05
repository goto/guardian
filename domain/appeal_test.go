package domain_test

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/assert"
)

func TestAppeal_GetNextPendingApproval(t *testing.T) {
	tests := []struct {
		name   string
		appeal domain.Appeal
		want   *domain.Approval
	}{
		{
			name: "should return nil if no approvals",
			appeal: domain.Appeal{
				Approvals: []*domain.Approval{},
			},
			want: nil,
		},
		{
			name: "should return pending approval if exists",
			appeal: domain.Appeal{
				Approvals: []*domain.Approval{
					{
						ID:        "1",
						Status:    domain.ApprovalStatusApproved,
						Approvers: []string{"user1"},
					},
					{
						ID:        "2",
						Status:    domain.ApprovalStatusPending,
						Approvers: []string{"user1"},
					},
				},
			},
			want: &domain.Approval{
				ID:        "2",
				Status:    domain.ApprovalStatusPending,
				Approvers: []string{"user1"},
			},
		},
		{
			name: "should return non-stale pending approval",
			appeal: domain.Appeal{
				Approvals: []*domain.Approval{
					{
						ID:        "1a",
						Status:    domain.ApprovalStatusApproved,
						Index:     0,
						Approvers: []string{"user1"},
						IsStale:   true,
					},
					{
						ID:        "2a",
						Status:    domain.ApprovalStatusApproved,
						Index:     0,
						Approvers: []string{"user1"},
					},
					{
						ID:        "1b",
						Status:    domain.ApprovalStatusPending,
						Index:     1,
						Approvers: []string{"user1"},
						IsStale:   true,
					},
					{
						ID:        "2b",
						Status:    domain.ApprovalStatusPending,
						Index:     1,
						Approvers: []string{"user1"},
					},
				},
			},
			want: &domain.Approval{
				ID:        "2b",
				Status:    domain.ApprovalStatusPending,
				Index:     1,
				Approvers: []string{"user1"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.appeal.GetNextPendingApproval(); !assert.Equal(t, got, tt.want) {
				t.Errorf("Appeal.GetNextPendingApproval() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAppeal_Init(t *testing.T) {
	a := domain.Appeal{}
	p := &domain.Policy{
		ID:      "policy-1",
		Version: 1,
	}
	a.Init(p)

	assert.Equal(t, a.Status, domain.AppealStatusPending)
	assert.Equal(t, a.PolicyID, p.ID)
	assert.Equal(t, a.PolicyVersion, p.Version)
}

func TestAppeal_Cancel(t *testing.T) {
	a := domain.Appeal{}
	a.Cancel()

	assert.Equal(t, a.Status, domain.AppealStatusCanceled)
}

func TestAppeal_Reject(t *testing.T) {
	a := domain.Appeal{}
	a.Reject()

	assert.Equal(t, a.Status, domain.AppealStatusRejected)
}

func TestAppeal_Approve(t *testing.T) {
	tests := []struct {
		name    string
		appeal  *domain.Appeal
		checks  func(t *testing.T, a *domain.Appeal)
		wantErr bool
	}{
		{
			name:   "should change status to approved",
			appeal: &domain.Appeal{},
			checks: func(t *testing.T, a *domain.Appeal) {
				t.Helper()
				assert.Equal(t, a.Status, domain.AppealStatusApproved)
			},
			wantErr: false,
		},
		{
			name: "should return error if duration is not valid",
			appeal: &domain.Appeal{
				Options: &domain.AppealOptions{
					Duration: "invalid",
				},
			},
			wantErr: true,
		},
		{
			name: "should be able to approve with permanent access",
			appeal: &domain.Appeal{
				Options: &domain.AppealOptions{
					Duration: "0",
				},
			},
			checks: func(t *testing.T, a *domain.Appeal) {
				t.Helper()
				assert.Equal(t, a.Status, domain.AppealStatusApproved)
			},
			wantErr: false,
		},
		{
			name: "should be able to approve with temporary access",
			appeal: &domain.Appeal{
				Options: &domain.AppealOptions{
					Duration: "1h",
				},
			},
			checks: func(t *testing.T, a *domain.Appeal) {
				t.Helper()
				assert.Equal(t, a.Status, domain.AppealStatusApproved)
				oneHourLater := time.Now().Add(1 * time.Hour)
				assert.GreaterOrEqual(t, oneHourLater, *a.Options.ExpirationDate)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.appeal.Approve(); (err != nil) != tt.wantErr {
				t.Errorf("Appeal.Approve() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.checks != nil {
				tt.checks(t, tt.appeal)
			}
		})
	}
}

func TestAppeal_SetDefaults(t *testing.T) {
	tests := []struct {
		name   string
		appeal *domain.Appeal
		checks func(t *testing.T, a *domain.Appeal)
	}{
		{
			name:   "should set default values if account type is not set",
			appeal: &domain.Appeal{},
			checks: func(t *testing.T, a *domain.Appeal) {
				t.Helper()
				assert.Equal(t, a.AccountType, domain.DefaultAppealAccountType)
			},
		},
		{
			name: "should set default values if account type is set",
			appeal: &domain.Appeal{
				AccountType: "test",
			},
			checks: func(t *testing.T, a *domain.Appeal) {
				t.Helper()
				assert.Equal(t, a.AccountType, "test")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.appeal.SetDefaults()
			tt.checks(t, tt.appeal)
		})
	}
}

func TestAppeal_GetApproval(t *testing.T) {
	tests := []struct {
		name   string
		appeal *domain.Appeal
		id     string
		want   *domain.Approval
	}{
		{
			name: "should return approval with given id",
			appeal: &domain.Appeal{
				Approvals: []*domain.Approval{
					{
						ID:      "approval_id_1",
						Name:    "approval_name",
						IsStale: true,
					},
					{
						ID:   "approval_id_2",
						Name: "approval_name",
					},
				},
			},
			id: "approval_id_1",
			want: &domain.Approval{
				ID:      "approval_id_1",
				Name:    "approval_name",
				IsStale: true,
			},
		},
		{
			name: "should return nil if approval with given id does not exist",
			appeal: &domain.Appeal{
				Approvals: []*domain.Approval{
					{
						ID: "approval_id_1",
					},
				},
			},
			id:   "non-existing",
			want: nil,
		},
		{
			name: "return the non-stale approval with the given name",
			appeal: &domain.Appeal{
				Approvals: []*domain.Approval{
					{
						ID:      "approval_id_1",
						Name:    "approval_name",
						IsStale: true,
					},
					{
						ID:   "approval_id_2",
						Name: "approval_name",
					},
				},
			},
			id: "approval_name",
			want: &domain.Approval{
				ID:   "approval_id_2",
				Name: "approval_name",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.appeal.GetApproval(tt.id); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Appeal.GetApproval() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAppeal_GetApprovalByIndex(t *testing.T) {
	testCases := []struct {
		name   string
		appeal *domain.Appeal
		index  int
		want   *domain.Approval
	}{
		{
			name: "should return approval with given index",
			appeal: &domain.Appeal{
				Approvals: []*domain.Approval{
					{
						ID:    "approval_id_1",
						Name:  "approval_name",
						Index: 0,
					},
					{
						ID:    "approval_id_2",
						Name:  "approval_name",
						Index: 1,
					},
				},
			},
			index: 1,
			want: &domain.Approval{
				ID:    "approval_id_2",
				Name:  "approval_name",
				Index: 1,
			},
		},
		{
			name: "should return nil if approval with given index does not exist",
			appeal: &domain.Appeal{
				Approvals: []*domain.Approval{
					{
						ID:    "approval_id_1",
						Index: 0,
					},
				},
			},
			index: 1,
			want:  nil,
		},
		{
			name: "should return non-stale approval with given index",
			appeal: &domain.Appeal{
				Approvals: []*domain.Approval{
					{
						ID:      "approval_id_1a",
						Index:   0,
						IsStale: true,
					},
					{
						ID:    "approval_id_1b",
						Index: 0,
					},
					{
						ID:      "approval_id_1c",
						Index:   0,
						IsStale: true,
					},
				},
			},
			index: 0,
			want: &domain.Approval{
				ID:    "approval_id_1b",
				Index: 0,
			},
		},
		{
			name: "should return non-stale approval with given index #2",
			appeal: &domain.Appeal{
				Approvals: []*domain.Approval{
					{
						ID:      "approval_id_1a",
						Index:   0,
						IsStale: true,
					},
					{
						ID:    "approval_id_1b",
						Index: 0,
					},
					{
						ID:      "approval_id_1c",
						Index:   0,
						IsStale: true,
					},
					{
						ID:      "approval_id_2a",
						Index:   1,
						IsStale: true,
					},
					{
						ID:      "approval_id_2b",
						Index:   1,
						IsStale: true,
					},
					{
						ID:    "approval_id_2c",
						Index: 1,
					},
				},
			},
			index: 1,
			want: &domain.Approval{
				ID:    "approval_id_2c",
				Index: 1,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.appeal.GetApprovalByIndex(tc.index)
			assert.Equal(t, tc.want, actual)
		})
	}
}

func TestAppeal_ToGrant(t *testing.T) {
	tests := []struct {
		name    string
		appeal  domain.Appeal
		want    *domain.Grant
		wantErr bool
	}{
		{
			name: "should return permanent grant",
			appeal: domain.Appeal{
				ID:          "appeal-1",
				AccountID:   "account-1",
				AccountType: "test",
				ResourceID:  "resource-1",
				Role:        "role-1",
				Permissions: []string{"permission-1"},
				CreatedBy:   "user-1",
			},
			want: &domain.Grant{
				Status:      domain.GrantStatusActive,
				AccountID:   "account-1",
				AccountType: "test",
				ResourceID:  "resource-1",
				Role:        "role-1",
				Permissions: []string{"permission-1"},
				AppealID:    "appeal-1",
				CreatedBy:   "user-1",
				IsPermanent: true,
			},
			wantErr: false,
		},
		{
			name: "should return permanent grant if duration is zero",
			appeal: domain.Appeal{
				ID:          "appeal-1",
				AccountID:   "account-1",
				AccountType: "test",
				ResourceID:  "resource-1",
				Role:        "role-1",
				Permissions: []string{"permission-1"},
				CreatedBy:   "user-1",
				Options: &domain.AppealOptions{
					Duration: "0",
				},
			},
			want: &domain.Grant{
				Status:      domain.GrantStatusActive,
				AccountID:   "account-1",
				AccountType: "test",
				ResourceID:  "resource-1",
				Role:        "role-1",
				Permissions: []string{"permission-1"},
				AppealID:    "appeal-1",
				CreatedBy:   "user-1",
				IsPermanent: true,
			},
			wantErr: false,
		},
		{
			name: "should return temporary grant if duration is not zero",
			appeal: domain.Appeal{
				ID:          "appeal-1",
				AccountID:   "account-1",
				AccountType: "test",
				ResourceID:  "resource-1",
				Role:        "role-1",
				Permissions: []string{"permission-1"},
				CreatedBy:   "user-1",
				Options: &domain.AppealOptions{
					Duration: "1h",
				},
			},
			want: &domain.Grant{
				Status:      domain.GrantStatusActive,
				AccountID:   "account-1",
				AccountType: "test",
				ResourceID:  "resource-1",
				Role:        "role-1",
				Permissions: []string{"permission-1"},
				AppealID:    "appeal-1",
				CreatedBy:   "user-1",
				IsPermanent: false,
			},
			wantErr: false,
		},
		{
			name: "should return error if invalid duration",
			appeal: domain.Appeal{
				ID:          "appeal-1",
				AccountID:   "account-1",
				AccountType: "test",
				ResourceID:  "resource-1",
				Role:        "role-1",
				Permissions: []string{"permission-1"},
				CreatedBy:   "user-1",
				Options: &domain.AppealOptions{
					Duration: "invalid",
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "should return error when both ExpirationDate and Duration are provided",
			appeal: domain.Appeal{
				ID:          "appeal-1",
				AccountID:   "account-1",
				AccountType: "test",
				ResourceID:  "resource-1",
				Role:        "role-1",
				Permissions: []string{"permission-1"},
				CreatedBy:   "user-1",
				Options: &domain.AppealOptions{
					ExpirationDate: func() *time.Time {
						t := time.Now().Add(24 * time.Hour)
						return &t
					}(),
					Duration: "48h",
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "should include group fields in ToGrant conversion",
			appeal: domain.Appeal{
				ID:          "appeal-1",
				AccountID:   "user@example.com",
				AccountType: "user",
				GroupID:     "group-123",
				GroupType:   "department",
				ResourceID:  "resource-1",
				Role:        "viewer",
				CreatedBy:   "user@example.com",
				Options: &domain.AppealOptions{
					Duration: "0h",
				},
			},
			want: &domain.Grant{
				Status:      domain.GrantStatusActive,
				AccountID:   "user@example.com",
				AccountType: "user",
				GroupID:     "group-123",
				GroupType:   "department",
				ResourceID:  "resource-1",
				Role:        "viewer",
				AppealID:    "appeal-1",
				CreatedBy:   "user@example.com",
				IsPermanent: true,
			},
			wantErr: false,
		},
		{
			name: "should work with empty group fields",
			appeal: domain.Appeal{
				ID:          "appeal-1",
				AccountID:   "user@example.com",
				AccountType: "user",
				ResourceID:  "resource-1",
				Role:        "viewer",
				CreatedBy:   "user@example.com",
				Options: &domain.AppealOptions{
					Duration: "24h",
				},
			},
			want: &domain.Grant{
				Status:      domain.GrantStatusActive,
				AccountID:   "user@example.com",
				AccountType: "user",
				ResourceID:  "resource-1",
				Role:        "viewer",
				AppealID:    "appeal-1",
				CreatedBy:   "user@example.com",
				IsPermanent: false,
			},
			wantErr: false,
		},
		{
			name: "should create grant with ExpirationDate and calculate Duration",
			appeal: domain.Appeal{
				ID:          "appeal-1",
				AccountID:   "account-1",
				AccountType: "test",
				ResourceID:  "resource-1",
				Role:        "role-1",
				Permissions: []string{"permission-1"},
				CreatedBy:   "user-1",
				Options: &domain.AppealOptions{
					ExpirationDate: func() *time.Time {
						t := time.Now().Add(48 * time.Hour)
						return &t
					}(),
				},
			},
			want: &domain.Grant{
				Status:      domain.GrantStatusActive,
				AccountID:   "account-1",
				AccountType: "test",
				ResourceID:  "resource-1",
				Role:        "role-1",
				Permissions: []string{"permission-1"},
				AppealID:    "appeal-1",
				CreatedBy:   "user-1",
				IsPermanent: false,
			},
			wantErr: false,
		},
		{
			name: "should return error when ExpirationDate is in the past",
			appeal: domain.Appeal{
				ID:          "appeal-1",
				AccountID:   "account-1",
				AccountType: "test",
				ResourceID:  "resource-1",
				Role:        "role-1",
				Permissions: []string{"permission-1"},
				CreatedBy:   "user-1",
				Options: &domain.AppealOptions{
					ExpirationDate: func() *time.Time {
						t := time.Now().Add(-24 * time.Hour)
						return &t
					}(),
				},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.appeal.ToGrant()
			if (err != nil) != tt.wantErr {
				t.Errorf("Appeal.ToGrant() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr == false && tt.want.IsPermanent == false {
				tt.want.ExpirationDate = got.ExpirationDate
				tt.want.RequestedExpirationDate = got.RequestedExpirationDate
				tt.want.ExpirationDateReason = domain.ExpirationDateReasonFromAppeal
			}
			if !assert.Equal(t, got, tt.want) {
				t.Errorf("Appeal.ToGrant() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAppeal_AdvanceApproval(t *testing.T) {
	tests := []struct {
		name          string
		appeal        *domain.Appeal
		wantErr       bool
		wantApprovals []*domain.Approval
	}{
		{
			name: "should resolve multiple automatic approval steps",
			appeal: &domain.Appeal{
				PolicyID:      "test-id",
				PolicyVersion: 1,
				Resource: &domain.Resource{
					Name: "grafana",
					Details: map[string]interface{}{
						"owner": "test-owner",
					},
				},
				Policy: &domain.Policy{
					ID:      "test-id",
					Version: 1,
					Steps: []*domain.Step{
						{
							Name:      "step-1",
							Strategy:  "auto",
							ApproveIf: `$appeal.resource.details.owner == "test-owner"`,
						},
						{
							Name:      "step-2",
							Strategy:  "auto",
							ApproveIf: `$appeal.resource.details.owner == "test-owner"`,
						},
						{
							Name:      "step-3",
							Strategy:  "auto",
							ApproveIf: `$appeal.resource.details.owner == "test-owner"`,
						},
					},
				},
				Approvals: []*domain.Approval{
					{
						Status: domain.ApprovalStatusPending,
						Index:  0,
					},
					{
						Status: domain.ApprovalStatusBlocked,
						Index:  1,
					},
					{
						Status: domain.ApprovalStatusBlocked,
						Index:  2,
					},
				},
			},
			wantErr: false,
			wantApprovals: []*domain.Approval{
				{
					Status: domain.ApprovalStatusApproved,
					Index:  0,
				},
				{
					Status: domain.ApprovalStatusApproved,
					Index:  1,
				},
				{
					Status: domain.ApprovalStatusApproved,
					Index:  2,
				},
			},
		},
		{
			name: "should autofill rejection reason on auto-reject",
			appeal: &domain.Appeal{
				PolicyID:      "test-id",
				PolicyVersion: 1,
				Resource: &domain.Resource{
					Name: "grafana",
					Details: map[string]interface{}{
						"owner": "test-owner",
					},
				},
				Policy: &domain.Policy{
					ID:      "test-id",
					Version: 1,
					Steps: []*domain.Step{
						{
							Name:            "step-1",
							Strategy:        "auto",
							RejectionReason: "test rejection reason",
							ApproveIf:       `false`, // hard reject for testing purpose
						},
					},
				},
				Approvals: []*domain.Approval{
					{
						Status: domain.ApprovalStatusPending,
						Index:  0,
					},
				},
			},
			wantErr: false,
			wantApprovals: []*domain.Approval{
				{
					Status: domain.ApprovalStatusRejected,
					Index:  0,
					Reason: "test rejection reason",
				},
			},
		},
		{
			name: "should do nothing if approvals is already rejected",
			appeal: &domain.Appeal{
				PolicyID:      "test-id",
				PolicyVersion: 1,
				Resource: &domain.Resource{
					Name: "grafana",
					Details: map[string]interface{}{
						"owner": "test-owner",
					},
				},
				Policy: &domain.Policy{
					ID:      "test-id",
					Version: 1,
					Steps: []*domain.Step{
						{
							Name:            "step-1",
							Strategy:        "auto",
							RejectionReason: "test rejection reason",
							ApproveIf:       `false`, // hard reject for testing purpose
						},
					},
				},
				Approvals: []*domain.Approval{
					{
						Status: domain.AppealStatusRejected,
						Index:  0,
					},
				},
			},
			wantErr: false,
			wantApprovals: []*domain.Approval{
				{
					Status: domain.ApprovalStatusRejected,
					Index:  0,
				},
			},
		},
		{
			name: "should return error if invalid expression",
			appeal: &domain.Appeal{
				PolicyID:      "test-id",
				PolicyVersion: 1,
				Resource: &domain.Resource{
					Name: "grafana",
					Details: map[string]interface{}{
						"owner": "test-owner",
					},
				},
				Policy: &domain.Policy{
					ID:      "test-id",
					Version: 1,
					Steps: []*domain.Step{
						{
							Name:      "step-1",
							Strategy:  "auto",
							ApproveIf: `)*(&_#)($U#_)(`, // invalid expression
						},
					},
				},
				Approvals: []*domain.Approval{
					{
						Status: domain.ApprovalStatusPending,
						Index:  0,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "should mark approval as skipped if auto approval condition is not met but AllowFailed=true",
			appeal: &domain.Appeal{
				PolicyID:      "test-id",
				PolicyVersion: 1,
				Resource: &domain.Resource{
					Name: "grafana",
					Details: map[string]interface{}{
						"owner": "test-owner",
					},
				},
				Policy: &domain.Policy{
					ID:      "test-id",
					Version: 1,
					Steps: []*domain.Step{
						{
							Name:        "step-1",
							Strategy:    "auto",
							ApproveIf:   "false",
							AllowFailed: true,
						},
						{
							Name:        "step-2",
							Strategy:    "manual",
							Approvers:   []string{"user@example.com"},
							AllowFailed: true,
						},
					},
				},
				Approvals: []*domain.Approval{
					{
						Name:   "step-1",
						Status: domain.ApprovalStatusPending,
						Index:  0,
					},
					{
						Name:   "step-2",
						Status: domain.ApprovalStatusBlocked,
						Index:  1,
					},
				},
			},
			wantErr: false,
			wantApprovals: []*domain.Approval{
				{
					Name:   "step-1",
					Status: domain.ApprovalStatusSkipped,
					Index:  0,
				},
				{
					Name:   "step-2",
					Status: domain.ApprovalStatusPending,
					Index:  1,
				},
			},
		},
		{
			name: "should handle mix of policy steps and custom steps",
			appeal: &domain.Appeal{
				PolicyID:      "test-id",
				PolicyVersion: 1,
				Resource: &domain.Resource{
					Details: map[string]interface{}{
						"owner": "test-owner",
					},
				},
				Policy: &domain.Policy{
					ID:      "test-id",
					Version: 1,
					Steps: []*domain.Step{
						{
							Name:      "step-1",
							Strategy:  "auto",
							ApproveIf: `$appeal.resource.details.owner == "test-owner"`,
						},
						{
							Name:      "step-2",
							Strategy:  "manual",
							Approvers: []string{"admin@example.com"},
						},
					},
					CustomSteps: &domain.CustomSteps{
						Type: "http",
					},
				},
				Approvals: []*domain.Approval{
					{
						Name:   "step-1",
						Status: domain.ApprovalStatusPending,
						Index:  0,
					},
					{
						Name:   "step-2",
						Status: domain.ApprovalStatusBlocked,
						Index:  1,
					},
					{
						Name:   "custom-step-1",
						Status: domain.ApprovalStatusBlocked,
						Index:  2,
					},
					{
						Name:   "custom-step-2",
						Status: domain.ApprovalStatusBlocked,
						Index:  3,
					},
				},
			},
			wantErr: false,
			wantApprovals: []*domain.Approval{
				{
					Name:   "step-1",
					Status: domain.ApprovalStatusApproved,
					Index:  0,
				},
				{
					Name:   "step-2",
					Status: domain.ApprovalStatusPending,
					Index:  1,
				},
				{
					Name:   "custom-step-1",
					Status: domain.ApprovalStatusBlocked,
					Index:  2,
				},
				{
					Name:   "custom-step-2",
					Status: domain.ApprovalStatusBlocked,
					Index:  3,
				},
			},
		},
		{
			name: "should not apply auto conditions to custom steps",
			appeal: &domain.Appeal{
				PolicyID:      "test-id",
				PolicyVersion: 1,
				Policy: &domain.Policy{
					ID:      "test-id",
					Version: 1,
					Steps: []*domain.Step{
						{
							Name:      "step-1",
							Strategy:  "auto",
							ApproveIf: `false`, // Would reject if applied
						},
					},
					CustomSteps: &domain.CustomSteps{
						Type: "http",
					},
				},
				Approvals: []*domain.Approval{
					{
						Name:   "step-1",
						Status: domain.ApprovalStatusApproved,
						Index:  0,
					},
					{
						Name:   "custom-step-1",
						Status: domain.ApprovalStatusPending,
						Index:  1,
					},
					{
						Name:   "custom-step-2",
						Status: domain.ApprovalStatusBlocked,
						Index:  2,
					},
				},
			},
			wantErr: false,
			wantApprovals: []*domain.Approval{
				{
					Name:   "step-1",
					Status: domain.ApprovalStatusApproved,
					Index:  0,
				},
				{
					Name:   "custom-step-1",
					Status: domain.ApprovalStatusPending, // Should remain pending
					Index:  1,
				},
				{
					Name:   "custom-step-2",
					Status: domain.ApprovalStatusBlocked,
					Index:  2,
				},
			},
		},
		{
			name: "should handle only custom steps without policy steps",
			appeal: &domain.Appeal{
				PolicyID:      "test-id",
				PolicyVersion: 1,
				Policy: &domain.Policy{
					ID:      "test-id",
					Version: 1,
					Steps:   []*domain.Step{}, // No policy steps
					CustomSteps: &domain.CustomSteps{
						Type: "http",
					},
				},
				Approvals: []*domain.Approval{
					{
						Name:   "custom-step-1",
						Status: domain.ApprovalStatusPending,
						Index:  0,
					},
					{
						Name:   "custom-step-2",
						Status: domain.ApprovalStatusBlocked,
						Index:  1,
					},
				},
			},
			wantErr: false,
			wantApprovals: []*domain.Approval{
				{
					Name:   "custom-step-1",
					Status: domain.ApprovalStatusPending, // No auto-processing
					Index:  0,
				},
				{
					Name:   "custom-step-2",
					Status: domain.ApprovalStatusBlocked,
					Index:  1,
				},
			},
		},
		{
			name: "should handle custom steps with skipped policy steps",
			appeal: &domain.Appeal{
				PolicyID:      "test-id",
				PolicyVersion: 1,
				Resource: &domain.Resource{
					Details: map[string]interface{}{
						"skip": true,
					},
				},
				Policy: &domain.Policy{
					ID:      "test-id",
					Version: 1,
					Steps: []*domain.Step{
						{
							Name:     "step-1",
							Strategy: "manual",
							When:     `!$appeal.resource.details.skip`, // Will be skipped
						},
						{
							Name:      "step-2",
							Strategy:  "auto",
							ApproveIf: `true`,
						},
					},
					CustomSteps: &domain.CustomSteps{
						Type: "http",
					},
				},
				Approvals: []*domain.Approval{
					{
						Name:   "step-1",
						Status: domain.ApprovalStatusPending,
						Index:  0,
					},
					{
						Name:   "step-2",
						Status: domain.ApprovalStatusBlocked,
						Index:  1,
					},
					{
						Name:   "custom-step-1",
						Status: domain.ApprovalStatusBlocked,
						Index:  2,
					},
				},
			},
			wantErr: false,
			wantApprovals: []*domain.Approval{
				{
					Name:   "step-1",
					Status: domain.ApprovalStatusSkipped,
					Index:  0,
				},
				{
					Name:   "step-2",
					Status: domain.ApprovalStatusApproved,
					Index:  1,
				},
				{
					Name:   "custom-step-1",
					Status: domain.ApprovalStatusPending,
					Index:  2,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.appeal.AdvanceApproval(tt.appeal.Policy); (err != nil) != tt.wantErr {
				t.Errorf("Appeal.AdvanceApproval() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantApprovals != nil {
				assert.Equal(t, tt.wantApprovals, tt.appeal.Approvals)
			}
		})
	}
}

func TestAppeal_AdvanceApproval_UpdateApprovalStatuses(t *testing.T) {
	resourceFlagStep := &domain.Step{
		Name: "resourceFlagStep",
		When: "$appeal.resource.details.flag == true",
		Approvers: []string{
			"user@email.com",
		},
	}
	humanApprovalStep := &domain.Step{
		Name: "humanApprovalStep",
		Approvers: []string{
			"human@email.com",
		},
	}

	testCases := []struct {
		name                     string
		appeal                   *domain.Appeal
		steps                    []*domain.Step
		existingApprovalStatuses []string
		expectedApprovalStatuses []string
		expectedErrorStr         string
	}{
		{
			name: "initial process, When on the first step",
			appeal: &domain.Appeal{
				Resource: &domain.Resource{
					Details: map[string]interface{}{
						"flag": false,
					},
				},
			},
			steps: []*domain.Step{
				resourceFlagStep,
				humanApprovalStep,
			},
			existingApprovalStatuses: []string{
				domain.ApprovalStatusPending,
				domain.ApprovalStatusBlocked,
			},
			expectedApprovalStatuses: []string{
				domain.ApprovalStatusSkipped,
				domain.ApprovalStatusPending,
			},
		},
		{
			name: "When expression fulfilled",
			appeal: &domain.Appeal{
				Resource: &domain.Resource{
					Details: map[string]interface{}{
						"flag": true,
					},
				},
			},
			steps: []*domain.Step{
				humanApprovalStep,
				resourceFlagStep,
				humanApprovalStep,
			},
			existingApprovalStatuses: []string{
				domain.ApprovalStatusApproved,
				domain.ApprovalStatusPending,
				domain.ApprovalStatusBlocked,
			},
			expectedApprovalStatuses: []string{
				domain.ApprovalStatusApproved,
				domain.ApprovalStatusPending,
				domain.ApprovalStatusBlocked,
			},
		},
		{
			name: "should access nested fields properly in expression",
			appeal: &domain.Appeal{
				Resource: &domain.Resource{},
			},
			steps: []*domain.Step{
				{
					Strategy:  "manual",
					When:      `$appeal.details != nil && $appeal.details.foo != nil && $appeal.details.bar != nil && ($appeal.details.foo.foo contains "foo" || $appeal.details.foo.bar contains "bar")`,
					Approvers: []string{"approver1@email.com"},
				},
				{
					Strategy:  "manual",
					Approvers: []string{"approver2@email.com"},
				},
			},
			existingApprovalStatuses: []string{
				domain.ApprovalStatusPending,
				domain.ApprovalStatusBlocked,
			},
			expectedApprovalStatuses: []string{
				domain.ApprovalStatusSkipped,
				domain.ApprovalStatusPending,
			},
		},
		{
			name: "should return error if failed when evaluating expression",
			appeal: &domain.Appeal{
				Resource: &domain.Resource{},
			},
			steps: []*domain.Step{
				{
					Strategy:  "manual",
					When:      `$appeal.details != nil && $appeal.details.foo != nil && $appeal.details.bar != nil && $appeal.details.foo.foo contains "foo" || $appeal.details.foo.bar contains "bar"`,
					Approvers: []string{"approver1@email.com"},
				},
				{
					Strategy:  "manual",
					Approvers: []string{"approver2@email.com"},
				},
			},
			existingApprovalStatuses: []string{
				domain.ApprovalStatusPending,
				domain.ApprovalStatusPending,
			},
			expectedErrorStr: "evaluating expression ",
		},
		{
			name: "custom steps - advance approval with multiple custom steps",
			appeal: &domain.Appeal{
				Status: domain.AppealStatusPending,
				Policy: &domain.Policy{
					ID:      "policy-1",
					Version: 1,
					CustomSteps: &domain.CustomSteps{
						Type: "custom",
					},
				},
			},
			steps: []*domain.Step{},
			existingApprovalStatuses: []string{
				domain.ApprovalStatusApproved,
				domain.ApprovalStatusPending,
				domain.ApprovalStatusBlocked,
			},
			expectedApprovalStatuses: []string{
				domain.ApprovalStatusApproved,
				domain.ApprovalStatusPending, // Custom steps don't auto-advance
				domain.ApprovalStatusBlocked, // Remains blocked
			},
		},
		{
			name: "custom steps - complete all approvals",
			appeal: &domain.Appeal{
				Status: domain.AppealStatusPending,
				Policy: &domain.Policy{
					ID:      "policy-1",
					Version: 1,
					CustomSteps: &domain.CustomSteps{
						Type: "custom",
					},
				},
			},
			steps: []*domain.Step{},
			existingApprovalStatuses: []string{
				domain.ApprovalStatusApproved,
				domain.ApprovalStatusApproved,
				domain.ApprovalStatusApproved,
			},
			expectedApprovalStatuses: []string{
				domain.ApprovalStatusApproved,
				domain.ApprovalStatusApproved,
				domain.ApprovalStatusApproved,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			appeal := *tc.appeal
			for i, s := range tc.existingApprovalStatuses {
				appeal.Approvals = append(appeal.Approvals, &domain.Approval{
					Status: s,
					Index:  i,
				})
			}
			if appeal.Policy == nil {
				appeal.Policy = &domain.Policy{}
			}
			appeal.Policy.Steps = tc.steps
			actualError := appeal.AdvanceApproval(appeal.Policy)
			if tc.expectedErrorStr == "" {
				assert.Nil(t, actualError)
				for i, a := range appeal.Approvals {
					assert.Equal(t, tc.expectedApprovalStatuses[i], a.Status)
				}
			} else {
				assert.Contains(t, actualError.Error(), tc.expectedErrorStr)
			}
		})
	}
}

func TestAppeal_ApplyPolicy(t *testing.T) {
	tests := []struct {
		name          string
		appeal        *domain.Appeal
		policy        *domain.Policy
		wantApprovals []*domain.Approval
		wantErr       bool
	}{
		{
			name:   "should return no approvals if steps are empty",
			appeal: &domain.Appeal{},
			policy: &domain.Policy{
				Steps: []*domain.Step{},
			},
			wantApprovals: []*domain.Approval{},
			wantErr:       false,
		},
		{
			name:   "should return correct approvals",
			appeal: &domain.Appeal{},
			policy: &domain.Policy{
				Steps: []*domain.Step{
					{
						Strategy:  domain.ApprovalStepStrategyAuto,
						ApproveIf: `1 == 1`,
					},
					{
						Strategy:  domain.ApprovalStepStrategyManual,
						Approvers: []string{"john.doe@example.com"},
					},
				},
			},
			wantApprovals: []*domain.Approval{
				{
					Index:  0,
					Status: domain.ApprovalStatusPending,
				},
				{
					Index:     1,
					Status:    domain.ApprovalStatusBlocked,
					Approvers: []string{"john.doe@example.com"},
				},
			},
			wantErr: false,
		},
		{
			name:   "should return error if failed to resolve approvers",
			appeal: &domain.Appeal{},
			policy: &domain.Policy{
				Steps: []*domain.Step{
					{
						Strategy:  domain.ApprovalStepStrategyManual,
						Approvers: []string{")*(@#&$_(*)#$&)(*"},
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.appeal.ApplyPolicy(tt.policy); (err != nil) != tt.wantErr {
				t.Errorf("Appeal.ApplyPolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
			assert.Equal(t, tt.appeal.Approvals, tt.wantApprovals)
		})
	}
}

func TestAppeal_Compare(t *testing.T) {
	testCases := []struct {
		name      string
		oldAppeal *domain.Appeal
		newAppeal *domain.Appeal
		wantDiff  []*domain.DiffItem
	}{
		{
			name: "should return empty diff if appeals are the same",
			oldAppeal: &domain.Appeal{
				ID: "appeal-1",
			},
			newAppeal: &domain.Appeal{
				ID: "appeal-1",
			},
			wantDiff: []*domain.DiffItem{},
		},
		{
			name: "should return diff if appeals are different",
			oldAppeal: &domain.Appeal{
				ID:          "appeal-1",
				ResourceID:  "resource-1",
				Role:        "role-1",
				Permissions: []string{"permission-1"},
				Options: &domain.AppealOptions{
					Duration: "24h",
				},
				Details: map[string]interface{}{
					domain.ReservedDetailsKeyPolicyQuestions: map[string]interface{}{
						"question-1": "answer-1",
						"question-2": "answer-2",
					},
				},
				PolicyID:      "policy-1",
				PolicyVersion: 1,
				CreatedBy:     "user@example.com",
			},
			newAppeal: &domain.Appeal{
				ID:          "appeal-1",
				ResourceID:  "resource-2",
				Role:        "role-2",
				Permissions: []string{"permission-2"},
				Options: &domain.AppealOptions{
					Duration: "48h",
				},
				Details: map[string]interface{}{
					domain.ReservedDetailsKeyPolicyQuestions: map[string]interface{}{
						"question-1": "answer-1-edit",
						"question-2": "answer-2-edit",
					},
					"extra": "extra-value",
				},
				PolicyID:      "policy-1",
				PolicyVersion: 2,
				CreatedBy:     "user@example.com",
			},
			wantDiff: []*domain.DiffItem{
				{
					Op:       "replace",
					Path:     "resource_id",
					OldValue: "resource-1",
					NewValue: "resource-2",
					Actor:    "user@example.com",
				},
				{
					Op:       "replace",
					Path:     "role",
					OldValue: "role-1",
					NewValue: "role-2",
					Actor:    "user@example.com",
				},
				{
					Op:       "replace",
					Path:     "permissions.0",
					OldValue: "permission-1",
					NewValue: "permission-2",
					Actor:    domain.SystemActorName,
				},
				{
					Op:       "replace",
					Path:     "options.duration",
					OldValue: "24h",
					NewValue: "48h",
					Actor:    "user@example.com",
				},
				{
					Op:       "replace",
					Path:     fmt.Sprintf("details.%s.question-1", domain.ReservedDetailsKeyPolicyQuestions),
					OldValue: "answer-1",
					NewValue: "answer-1-edit",
					Actor:    "user@example.com",
				},
				{
					Op:       "replace",
					Path:     fmt.Sprintf("details.%s.question-2", domain.ReservedDetailsKeyPolicyQuestions),
					OldValue: "answer-2",
					NewValue: "answer-2-edit",
					Actor:    "user@example.com",
				},
				{
					Op:       "add",
					Path:     "details.extra",
					NewValue: "extra-value",
					Actor:    "user@example.com",
				},
				{
					Op:       "replace",
					Path:     "policy_version",
					OldValue: float64(1),
					NewValue: float64(2),
					Actor:    domain.SystemActorName,
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualDiff, err := tc.newAppeal.Compare(tc.oldAppeal, "user@example.com")
			assert.NoError(t, err)
			assert.Empty(t, cmp.Diff(tc.wantDiff, actualDiff, cmpopts.SortSlices(func(a, b *domain.DiffItem) bool {
				return a.Path < b.Path || (a.Path == b.Path && a.Op < b.Op)
			})))
		})
	}
}

func TestApprovalAction_Validate(t *testing.T) {
	testCases := []struct {
		name string
		aa   domain.ApprovalAction
		want error
	}{
		{
			name: "PassingValidation",
			aa: domain.ApprovalAction{
				AppealID:     "appeal-1",
				ApprovalName: "approval-1",
				Actor:        "user@example.com",
				Action:       "approve",
			},
			want: nil,
		},
		{
			name: "EmptyAppealID",
			aa: domain.ApprovalAction{
				AppealID: "",
			},
			want: errors.New("appeal id is required"),
		},
		{
			name: "EmptyApprovalName",
			aa: domain.ApprovalAction{
				AppealID:     "appeal-1",
				ApprovalName: "",
			},
			want: errors.New("approval name is required"),
		},
		{
			name: "InvalidActor",
			aa: domain.ApprovalAction{
				AppealID:     "appeal-1",
				ApprovalName: "approval-1",
				Actor:        "invalid-email",
			},
			want: errors.New(`actor is not a valid email: "invalid-email"`),
		},
		{
			name: "InvalidAction",
			aa: domain.ApprovalAction{
				AppealID:     "appeal-1",
				ApprovalName: "approval-1",
				Actor:        "user@example.com",
				Action:       "invalid-action",
			},
			want: errors.New(`invalid action: "invalid-action"`),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualError := tc.aa.Validate()
			if tc.want == nil {
				assert.NoError(t, actualError)
			} else {
				assert.Error(t, actualError)
				assert.Equal(t, tc.want.Error(), actualError.Error())
			}
		})
	}
}
