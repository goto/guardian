package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestApproval_IsExistingApprover(t *testing.T) {
	a := &Approval{
		Approvers: []string{"user1@example.com", "user2@example.com", "user3@example.com"},
	}

	tests := []struct {
		name     string
		approver string
		want     bool
	}{
		{
			name:     "existing approver",
			approver: "user2@example.com",
			want:     true,
		},
		{
			name:     "non-existing approver",
			approver: "user4@example.com",
			want:     false,
		},
		{
			name:     "existing approver with lower case email",
			approver: "user1@example.com",
			want:     true,
		},
		{
			name:     "existing approver with upper case email",
			approver: "USER3@EXAMPLE.COM",
			want:     true,
		},
		{
			name:     "existing approver with mixed case email",
			approver: "UsEr2@ExAmPlE.CoM",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.IsExistingApprover(tt.approver); got != tt.want {
				t.Errorf("Approval.IsExistingApprover() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApproval_Approve(t *testing.T) {
	a := &Approval{Status: ApprovalStatusPending}
	a.Approve()
	assert.Equal(t, ApprovalStatusApproved, a.Status)
}

func TestApproval_Reject(t *testing.T) {
	a := &Approval{Status: ApprovalStatusPending}
	a.Reject()
	assert.Equal(t, ApprovalStatusRejected, a.Status)
}

func TestApproval_Skip(t *testing.T) {
	a := &Approval{Status: ApprovalStatusPending}
	a.Skip()
	assert.Equal(t, ApprovalStatusSkipped, a.Status)
}

func TestListApprovalsFilter_WithApprovals(t *testing.T) {
	assert.True(t, ListApprovalsFilter{}.WithApprovals())
	assert.False(t, ListApprovalsFilter{FieldMasks: []string{"approvals"}}.WithApprovals())
}

func TestListApprovalsFilter_WithTotal(t *testing.T) {
	assert.True(t, ListApprovalsFilter{}.WithTotal())
	assert.False(t, ListApprovalsFilter{FieldMasks: []string{"total"}}.WithTotal())
}

func TestListApprovalsFilter_WithSummary(t *testing.T) {
	assert.False(t, ListApprovalsFilter{}.WithSummary())
	assert.True(t, ListApprovalsFilter{SummaryGroupBys: []string{"status"}}.WithSummary())
	assert.True(t, ListApprovalsFilter{SummaryLabels: true}.WithSummary())
	assert.True(t, ListApprovalsFilter{SummaryLabelsV2: true}.WithSummary())
}
