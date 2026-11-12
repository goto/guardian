package domain_test

import (
	"testing"

	"github.com/goto/guardian/domain"
)

func TestNotificationCardFingerprintContract(t *testing.T) {
	ids := []string{"approval-1"}
	if got := domain.PendingNotificationCardHash(2, ids, "approver@example.com"); got != "c1f754b1662d398cb805cf821be1359fe358dccf1b3fa0de288c8257da6981b1" {
		t.Fatalf("worker fingerprint contract differs: %s", got)
	}
	a := &domain.Appeal{Revision: 2, Status: domain.AppealStatusApproved, Approvals: []*domain.Approval{{ID: "approval-1", Status: domain.ApprovalStatusApproved, AppealRevision: 2, Approvers: []string{"approver@example.com"}}}}
	if got := domain.NotificationCardStateHash(a, ids, "APPROVER@example.com"); got != "a991d18dcf40e2a1e36294288a961889f3c66e963c1db170697a41dd0230a284" {
		t.Fatalf("approved fingerprint differs: %s", got)
	}
}
