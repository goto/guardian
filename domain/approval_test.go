package domain

import (
	"testing"
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
