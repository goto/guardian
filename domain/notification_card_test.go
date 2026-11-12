package domain_test

import (
	"testing"

	"github.com/goto/guardian/domain"
)

func TestNotificationCardFingerprintContract(t *testing.T) {
	ids := []string{"approval-1"}
	if got := domain.PendingNotificationCardHash(2, ids, "approver@example.com"); got != "f3ba883bf74ac17f5b9e0a678ce6510249827e8a2a456bf43dfbf4ad7e80b63c" {
		t.Fatalf("worker fingerprint contract differs: %s", got)
	}
	a := &domain.Appeal{Revision: 2, Status: domain.AppealStatusApproved, Approvals: []*domain.Approval{{ID: "approval-1", Status: domain.ApprovalStatusApproved, AppealRevision: 2, Approvers: []string{"approver@example.com"}}}}
	if got := domain.NotificationCardStateHash(a, ids, "APPROVER@example.com"); got != "d60494f0e2114fdc3244bbac11b486ca94514cf0a5f1c7b0542ed12e92cd19ca" {
		t.Fatalf("approved fingerprint differs: %s", got)
	}
}
