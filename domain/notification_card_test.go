package domain_test

import (
	"testing"

	"github.com/goto/guardian/domain"
)

func TestNotificationCardFingerprintContract(t *testing.T) {
	ids := []string{"approval-1"}
	if got := domain.PendingNotificationCardHash(2, ids, "approver@example.com"); got != "3bcb015b6f2ed1cd24eace253b4b79200ba7d0c497e96a388564707f1ad458b4" {
		t.Fatalf("worker fingerprint contract differs: %s", got)
	}
	a := &domain.Appeal{Revision: 2, Status: domain.AppealStatusApproved, Approvals: []*domain.Approval{{ID: "approval-1", Status: domain.ApprovalStatusApproved, AppealRevision: 2, Approvers: []string{"approver@example.com"}}}}
	if got := domain.NotificationCardStateHash(a, ids, "APPROVER@example.com"); got != "72060ffe29670c4e1ed0cc0c42dd78d5481eaef60f45e59003dfc50ab1ba2b95" {
		t.Fatalf("approved fingerprint differs: %s", got)
	}
}
