package appeal_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/goto/guardian/core/appeal"
	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/mock"
)

func TestStaleCardRejectedBeforeProviderCalls(t *testing.T) {
	for _, action := range []string{"approve", "reject"} {
		t.Run(action, func(t *testing.T) {
			h := newServiceTestHelper()
			id := uuid.NewString()
			h.mockRepository.EXPECT().GetByID(mock.Anything, id).Return(&domain.Appeal{ID: id, Status: domain.AppealStatusPending, Revision: 2, Approvals: []*domain.Approval{{ID: "old-approval", Name: "owner", Status: domain.ApprovalStatusPending, IsStale: true, AppealRevision: 1}}}, nil).Once()
			_, err := h.service.UpdateApproval(context.Background(), domain.ApprovalAction{AppealID: id, ApprovalName: "old-approval", Actor: "approver@example.com", Action: action})
			if !errors.Is(err, appeal.ErrApprovalNotEligibleForAction) {
				t.Fatalf("got %v", err)
			}
			h.mockProviderService.AssertNotCalled(t, "GrantAccess", mock.Anything, mock.Anything)
			h.mockRepository.AssertNotCalled(t, "UpdateWithLock", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			h.mockRepository.AssertExpectations(t)
		})
	}
}

func TestStaleRevisionRecheckedInsideLockedCommit(t *testing.T) {
	h := newServiceTestHelper()
	id := uuid.NewString()
	initial := &domain.Appeal{ID: id, Status: domain.AppealStatusPending, Revision: 2, Approvals: []*domain.Approval{{ID: "approval", Name: "owner", Status: domain.ApprovalStatusPending, AppealRevision: 2, Approvers: []string{"approver@example.com"}}}}
	fresh := &domain.Appeal{ID: id, Status: domain.AppealStatusPending, Revision: 3, Approvals: []*domain.Approval{{ID: "approval", Name: "owner", Status: domain.ApprovalStatusPending, AppealRevision: 2, IsStale: true, Approvers: []string{"approver@example.com"}}}}
	h.mockRepository.EXPECT().GetByID(mock.Anything, id).Return(initial, nil).Once()
	h.mockRepository.EXPECT().UpdateWithLock(mock.Anything, id, (*domain.Grant)(nil), mock.Anything).RunAndReturn(func(ctx context.Context, id string, previous *domain.Grant, mutate func(*domain.Appeal) error) (*domain.Appeal, error) {
		return nil, mutate(fresh)
	}).Once()
	_, err := h.service.UpdateApproval(context.Background(), domain.ApprovalAction{AppealID: id, ApprovalName: "approval", Actor: "approver@example.com", Action: "reject", Reason: "Example reason"})
	if !errors.Is(err, appeal.ErrApprovalNotEligibleForAction) {
		t.Fatalf("got %v", err)
	}
	if fresh.Approvals[0].Actor != nil || fresh.Status != domain.AppealStatusPending {
		t.Fatal("stale revision mutated under lock")
	}
	h.mockRepository.AssertExpectations(t)
}
