package appeal_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/goto/guardian/core/appeal"
	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/mock"
)

func serviceParallelAppeal(id string) *domain.Appeal {
	return &domain.Appeal{ID: id, Status: domain.AppealStatusPending, Revision: 1, CreatedBy: "requester@example.com", Resource: &domain.Resource{Name: "Example"}, Options: &domain.AppealOptions{Duration: "24h"}, Policy: &domain.Policy{Steps: []*domain.Step{{Name: "A", Strategy: domain.ApprovalStepStrategyManual}, {Name: "B", Strategy: domain.ApprovalStepStrategyManual}, {Name: "C", Strategy: domain.ApprovalStepStrategyManual}}}, Approvals: []*domain.Approval{
		{ID: "a", Name: "A", Index: 0, Status: domain.ApprovalStatusPending, AppealRevision: 1, Approvers: []string{"a@example.com", "b@example.com"}},
		{ID: "b", Name: "B", Index: 1, Status: domain.ApprovalStatusBlocked, AppealRevision: 1, Approvers: []string{"c@example.com", "d@example.com"}},
		{ID: "c", Name: "C", Index: 1, Status: domain.ApprovalStatusBlocked, AppealRevision: 1, Approvers: []string{"d@example.com", "e@example.com"}},
	}}
}

func TestApprovalCommitCallsNotifierForNewParallelStage(t *testing.T) {
	h := newServiceTestHelper()
	defer h.assertExpectations(t)
	id := uuid.NewString()
	initial := serviceParallelAppeal(id)
	fresh := serviceParallelAppeal(id)
	h.mockRepository.EXPECT().GetByID(mock.Anything, id).Return(initial, nil).Once()
	h.mockRepository.EXPECT().UpdateWithLock(mock.Anything, id, (*domain.Grant)(nil), mock.Anything).RunAndReturn(func(ctx context.Context, id string, previous *domain.Grant, mutate func(*domain.Appeal) error) (*domain.Appeal, error) {
		if err := mutate(fresh); err != nil {
			return nil, err
		}
		return fresh, nil
	}).Once()
	captured := make(chan []domain.Notification, 1)
	h.mockNotifier.EXPECT().Notify(mock.Anything, mock.Anything).Run(func(ctx context.Context, items []domain.Notification) { captured <- items }).Return(nil).Once()
	h.mockAuditLogger.EXPECT().Log(mock.Anything, appeal.AuditKeyApprove, mock.Anything).Return(nil).Once()
	result, err := h.service.UpdateApproval(context.Background(), domain.ApprovalAction{AppealID: id, ApprovalName: "a", Actor: "a@example.com", Action: "approve"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Approvals[1].Status != domain.ApprovalStatusPending || result.Approvals[2].Status != domain.ApprovalStatusPending {
		t.Fatal("parallel stage not active after commit")
	}
	select {
	case items := <-captured:
		counts := map[string]int{}
		for _, item := range items {
			counts[item.User]++
		}
		if counts["c@example.com"] != 1 || counts["d@example.com"] != 2 || counts["e@example.com"] != 1 || counts["a@example.com"] != 0 {
			t.Fatalf("wrong stage notification batch: %+v", counts)
		}
	case <-time.After(time.Second):
		t.Fatal("approval completion did not invoke the notifier")
	}
}

func TestAddingApproverToBlockedStepDoesNotSendNotification(t *testing.T) {
	h := newServiceTestHelper()
	defer h.assertExpectations(t)
	id := uuid.NewString()
	a := serviceParallelAppeal(id)
	h.mockRepository.EXPECT().GetByID(mock.Anything, id).Return(a, nil).Once()
	h.mockApprovalService.EXPECT().AddApprover(mock.Anything, "b", "new@example.com").Return(nil).Once()
	h.mockAuditLogger.EXPECT().Log(mock.Anything, appeal.AuditKeyAddApprover, mock.Anything).Return(nil).Once()
	if _, err := h.service.AddApprover(context.Background(), id, "b", "new@example.com"); err != nil {
		t.Fatal(err)
	}
	h.mockNotifier.AssertNotCalled(t, "Notify", mock.Anything, mock.Anything)
}
