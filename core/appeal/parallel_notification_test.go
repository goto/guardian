package appeal

import (
	"context"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
)

func parallelNotificationAppeal() *domain.Appeal {
	return &domain.Appeal{ID: "appeal", Status: domain.AppealStatusPending, Revision: 1, CreatedBy: "requester@example.com", Resource: &domain.Resource{Name: "Example"}, Options: &domain.AppealOptions{Duration: "24h"}, Approvals: []*domain.Approval{
		{ID: "a", Name: "Step A", Index: 0, Status: domain.ApprovalStatusPending, AppealRevision: 1, Approvers: []string{"a@example.com", "b@example.com"}},
		{ID: "b", Name: "Step B", Index: 1, Status: domain.ApprovalStatusBlocked, AppealRevision: 1, Approvers: []string{"c@example.com", "d@example.com"}},
		{ID: "c", Name: "Step C", Index: 1, Status: domain.ApprovalStatusBlocked, AppealRevision: 1, Approvers: []string{"d@example.com", "e@example.com"}},
	}}
}

func TestCreationNotifiesOnlyPendingManualSteps(t *testing.T) {
	s := &Service{logger: log.NewNoop()}
	appeal := parallelNotificationAppeal()
	appeal.Approvals = append(appeal.Approvals, &domain.Approval{ID: "automatic", Name: "Automatic", Status: domain.ApprovalStatusPending, AppealRevision: 1}, &domain.Approval{ID: "stale", Name: "Stale", Status: domain.ApprovalStatusPending, AppealRevision: 1, IsStale: true, Approvers: []string{"stale@example.com"}}, &domain.Approval{ID: "old-revision", Name: "Old", Status: domain.ApprovalStatusPending, AppealRevision: 0, Approvers: []string{"old@example.com"}})
	notifications := s.getApprovalNotifications(context.Background(), appeal)
	if len(notifications) != 2 {
		t.Fatalf("expected only A's two recipients, got %d", len(notifications))
	}
	for _, n := range notifications {
		if n.Approval.ApprovalID != "a" || (n.User != "a@example.com" && n.User != "b@example.com") {
			t.Fatalf("blocked/stale/automatic recipient notified: %+v", n)
		}
	}
}

func TestApprovalUnlocksBothParallelStepsAndNotifiesAllRecipients(t *testing.T) {
	s := &Service{logger: log.NewNoop()}
	before := parallelNotificationAppeal()
	after := cloneAppealForMutation(before)
	policy := &domain.Policy{Steps: []*domain.Step{{Name: "Step A", Strategy: domain.ApprovalStepStrategyManual}, {Name: "Step B", Strategy: domain.ApprovalStepStrategyManual}, {Name: "Step C", Strategy: domain.ApprovalStepStrategyManual}}}
	if err := applyApprovalMutation(after, domain.ApprovalAction{ApprovalName: "a", Actor: "a@example.com", Action: "approve"}, policy); err != nil {
		t.Fatal(err)
	}
	if after.Approvals[1].Status != domain.ApprovalStatusPending || after.Approvals[2].Status != domain.ApprovalStatusPending {
		t.Fatal("parallel steps did not become pending")
	}
	notifications := s.getNewApprovalNotifications(context.Background(), before, after)
	steps := map[string][]string{}
	for _, n := range notifications {
		steps[n.User] = append(steps[n.User], n.Approval.ApprovalID)
	}
	if len(steps) != 3 || len(steps["c@example.com"]) != 1 || len(steps["d@example.com"]) != 2 || len(steps["e@example.com"]) != 1 {
		t.Fatalf("wrong newly eligible recipients: %+v", steps)
	}
	if steps["d@example.com"][0] != "b" || steps["d@example.com"][1] != "c" {
		t.Fatalf("D does not have both steps: %+v", steps)
	}
}

func TestParallelCompletionDoesNotRenotifyUnchangedPendingRecipients(t *testing.T) {
	s := &Service{logger: log.NewNoop()}
	before := parallelNotificationAppeal()
	before.Approvals[0].Status = domain.ApprovalStatusApproved
	before.Approvals[1].Status = domain.ApprovalStatusPending
	before.Approvals[2].Status = domain.ApprovalStatusPending
	after := cloneAppealForMutation(before)
	after.Approvals[1].Status = domain.ApprovalStatusApproved
	if got := s.getNewApprovalNotifications(context.Background(), before, after); len(got) != 0 {
		t.Fatalf("unchanged C recipients were notified again: %+v", got)
	}
}

func TestNewlyEligibleRecipientGetsAllTheirCurrentPendingSteps(t *testing.T) {
	s := &Service{logger: log.NewNoop()}
	before := parallelNotificationAppeal()
	before.Approvals[0].Status = domain.ApprovalStatusApproved
	before.Approvals[1].Status = domain.ApprovalStatusPending
	after := cloneAppealForMutation(before)
	after.Approvals[2].Status = domain.ApprovalStatusPending
	notifications := s.getNewApprovalNotifications(context.Background(), before, after)
	counts := map[string]int{}
	for _, n := range notifications {
		counts[n.User]++
	}
	if counts["d@example.com"] != 2 || counts["e@example.com"] != 1 || counts["c@example.com"] != 0 {
		t.Fatalf("incomplete merged context or duplicate notification: %+v", counts)
	}
}

func TestSequentialStageNotifiesOnlyAfterParallelStageCompletes(t *testing.T) {
	s := &Service{logger: log.NewNoop()}
	before := parallelNotificationAppeal()
	before.Approvals[0].Status = domain.ApprovalStatusApproved
	before.Approvals[1].Status = domain.ApprovalStatusApproved
	before.Approvals[2].Status = domain.ApprovalStatusPending
	before.Approvals = append(before.Approvals, &domain.Approval{ID: "next", Name: "Next stage", Index: 2, Status: domain.ApprovalStatusBlocked, AppealRevision: 1, Approvers: []string{"next@example.com"}})
	if got := s.getNewApprovalNotifications(context.Background(), before, before); len(got) != 0 {
		t.Fatal("blocked next stage was notified")
	}
	after := cloneAppealForMutation(before)
	policy := &domain.Policy{Steps: []*domain.Step{{Name: "Step A", Strategy: domain.ApprovalStepStrategyManual}, {Name: "Step B", Strategy: domain.ApprovalStepStrategyManual}, {Name: "Step C", Strategy: domain.ApprovalStepStrategyManual}, {Name: "Next stage", Strategy: domain.ApprovalStepStrategyManual}}}
	if err := applyApprovalMutation(after, domain.ApprovalAction{ApprovalName: "c", Actor: "e@example.com", Action: "approve"}, policy); err != nil {
		t.Fatal(err)
	}
	got := s.getNewApprovalNotifications(context.Background(), before, after)
	if len(got) != 1 || got[0].User != "next@example.com" || got[0].Approval.ApprovalID != "next" {
		t.Fatalf("wrong next stage: %+v", got)
	}
}
