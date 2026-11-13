package domain_test

import (
	"testing"

	"github.com/goto/guardian/domain"
)

func TestNotificationCardFingerprintContract(t *testing.T) {
	ids := []string{"approval-1"}
	if got := domain.PendingNotificationCardHash(2, ids, "approver@example.com"); got != "c7b575a79216aac384d011ee952abfd6281b392717025f7f767dbca7fc75e894" {
		t.Fatalf("worker fingerprint contract differs: %s", got)
	}
	a := &domain.Appeal{Revision: 2, Status: domain.AppealStatusApproved, Approvals: []*domain.Approval{{ID: "approval-1", Status: domain.ApprovalStatusApproved, AppealRevision: 2, Approvers: []string{"approver@example.com"}}}}
	if got := domain.NotificationCardStateHash(a, ids, "APPROVER@example.com"); got != "f0ef9a58ec11a32018bb9aa61aad21b174163fb3b7cbbfc72e5f8475794d8706" {
		t.Fatalf("approved fingerprint differs: %s", got)
	}
}
