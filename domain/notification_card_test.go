package domain_test

import (
	"testing"
	"time"

	"github.com/goto/guardian/domain"
)

func TestNotificationCardFingerprintContract(t *testing.T) {
	ids := []string{"approval-1"}
	if got := domain.PendingNotificationCardHash(2, ids, "approver@example.com"); got != "4414b77d8bc19982149150129a31e4a4891fe981d33cfe0da41fe0ce74746be2" {
		t.Fatalf("worker fingerprint contract differs: %s", got)
	}
	a := &domain.Appeal{Revision: 2, Status: domain.AppealStatusApproved, Approvals: []*domain.Approval{{ID: "approval-1", Status: domain.ApprovalStatusApproved, AppealRevision: 2, Approvers: []string{"approver@example.com"}}}}
	if got := domain.NotificationCardStateHash(a, ids, "APPROVER@example.com"); got != "fcd6150a58e14bc9f23073b72396ae2375e069320692c94423453104200e6933" {
		t.Fatalf("approved fingerprint differs: %s", got)
	}
}

func TestQuestionAndApproverFingerprintContract(t *testing.T) {
	updated, _ := time.Parse(time.RFC3339, "2026-11-16T13:00:00+07:00")
	a := &domain.Appeal{Revision: 2, Status: "pending", UpdatedAt: updated, Details: map[string]interface{}{"__policy_questions": map[string]interface{}{"business_reason": " Review reports ", "systems": []string{"one", "two"}, "optional": " ", " ": "ignored"}}, Approvals: []*domain.Approval{{ID: "approval-1", Name: "owner", Status: "pending", AppealRevision: 2, Approvers: []string{"OTHER@example.com", "approver@example.com"}}}}
	ids := []string{"approval-1"}
	before := domain.NotificationCardStateHash(a, ids, "approver@example.com")
	if before != "779782e6e9110029f29681e8dba4f3c81ef8192bf654005123d3f86dcbebb696" {
		t.Fatalf("worker full context contract differs:%s", before)
	}
	a.Details["__policy_questions"].(map[string]interface{})["business_reason"] = "Changed reason"
	if domain.NotificationCardStateHash(a, ids, "approver@example.com") == before {
		t.Fatal("answer change was ignored")
	}
	before = domain.NotificationCardStateHash(a, ids, "approver@example.com")
	a.Approvals[0].Approvers = []string{"approver@example.com"}
	if domain.NotificationCardStateHash(a, ids, "approver@example.com") == before {
		t.Fatal("other approver change was ignored")
	}
}
