package domain_test

import (
	"testing"

	"github.com/goto/guardian/domain"
)

func TestNotificationCardFingerprintContract(t *testing.T) {
	ids := []string{"approval-1"}
	if got := domain.PendingNotificationCardHash(2, ids, "approver@example.com"); got != "9e101eb7fcfc004328b47d6e4151b1505d4b534bdb95d2489565841c8f20451e" {
		t.Fatalf("worker fingerprint contract differs: %s", got)
	}
	a := &domain.Appeal{Revision: 2, Status: domain.AppealStatusApproved, Approvals: []*domain.Approval{{ID: "approval-1", Status: domain.ApprovalStatusApproved, AppealRevision: 2, Approvers: []string{"approver@example.com"}}}}
	if got := domain.NotificationCardStateHash(a, ids, "APPROVER@example.com"); got != "4025bc9b51ead98bd98c183651621f6b6256f7f7c631258bc94650c7aa7d9ee4" {
		t.Fatalf("approved fingerprint differs: %s", got)
	}
}
