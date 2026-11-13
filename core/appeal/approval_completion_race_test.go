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

func completionSnapshot(id string, otherApproved bool) *domain.Appeal {
	other := domain.ApprovalStatusPending
	if otherApproved {
		other = domain.ApprovalStatusApproved
	}
	return &domain.Appeal{ID: id, Status: domain.AppealStatusPending, CreatedBy: "requester@example.com", AccountID: "requester@example.com", ResourceID: "resource", Role: "reader", Resource: &domain.Resource{ID: "resource", Name: "Example", ProviderType: "example", Type: "dataset"}, Options: &domain.AppealOptions{Duration: "24h"}, Policy: &domain.Policy{Steps: []*domain.Step{{Name: "B", Strategy: domain.ApprovalStepStrategyManual}, {Name: "C", Strategy: domain.ApprovalStepStrategyManual}}}, Approvals: []*domain.Approval{{ID: "b", Name: "B", Index: 0, Status: domain.ApprovalStatusPending, Approvers: []string{"b@example.com"}}, {ID: "c", Name: "C", Index: 0, Status: other, Approvers: []string{"c@example.com"}}}}
}

func TestParallelCompletionRetriesBeforeCommittingApproved(t *testing.T) {
	h := newServiceTestHelper()
	defer h.assertExpectations(t)
	id := uuid.NewString()
	action := domain.ApprovalAction{AppealID: id, ApprovalName: "b", Actor: "b@example.com", Action: "approve"}
	h.mockRepository.EXPECT().GetByID(mock.Anything, id).Return(completionSnapshot(id, false), nil).Once()
	h.mockRepository.EXPECT().GetByID(mock.Anything, id).Return(completionSnapshot(id, true), nil).Once()
	prepared := &domain.Grant{ID: uuid.NewString(), Status: domain.GrantStatusActive, AccountID: "requester@example.com", ResourceID: "resource", Role: "reader"}
	h.mockProviderService.EXPECT().IsExclusiveRoleAssignment(mock.Anything, "example", "dataset").Return(false).Once()
	h.mockGrantService.EXPECT().List(mock.Anything, mock.Anything).Return([]domain.Grant{}, nil).Once()
	h.mockGrantService.EXPECT().Prepare(mock.Anything, mock.Anything).Return(prepared, nil).Once()
	h.mockProviderService.EXPECT().GetDependencyGrants(mock.Anything, mock.Anything).Return(nil, nil).Once()
	h.mockProviderService.EXPECT().GrantAccess(mock.Anything, mock.Anything).Return(nil).Once()
	commits := 0
	attempts := 0
	h.mockRepository.EXPECT().UpdateWithLock(mock.Anything, id, (*domain.Grant)(nil), mock.Anything).RunAndReturn(func(ctx context.Context, id string, old *domain.Grant, mutate func(*domain.Appeal) error) (*domain.Appeal, error) {
		attempts++
		fresh := completionSnapshot(id, true)
		if err := mutate(fresh); err != nil {
			return nil, err
		}
		if fresh.Status == domain.AppealStatusApproved && fresh.Grant == nil {
			t.Fatal("would commit Approved without prepared grant")
		}
		commits++
		return fresh, nil
	}).Twice()
	h.mockNotifier.EXPECT().Notify(mock.Anything, mock.Anything).Return(nil).Once()
	h.mockAuditLogger.EXPECT().Log(mock.Anything, appeal.AuditKeyApprove, mock.Anything).Return(nil).Once()
	result, err := h.service.UpdateApproval(context.Background(), action)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.AppealStatusApproved || result.Grant == nil || result.Grant.ID != prepared.ID || attempts != 2 || commits != 1 {
		t.Fatalf("unsafe completion: result=%+v attempts=%d commits=%d", result, attempts, commits)
	}
}

func TestParallelCompletionRetryIsBoundedAndRunsNoGrantSideEffects(t *testing.T) {
	h := newServiceTestHelper()
	defer h.assertExpectations(t)
	id := uuid.NewString()
	h.mockRepository.EXPECT().GetByID(mock.Anything, id).Return(completionSnapshot(id, false), nil).Times(3)
	h.mockRepository.EXPECT().UpdateWithLock(mock.Anything, id, (*domain.Grant)(nil), mock.Anything).RunAndReturn(func(ctx context.Context, id string, old *domain.Grant, mutate func(*domain.Appeal) error) (*domain.Appeal, error) {
		return nil, mutate(completionSnapshot(id, true))
	}).Times(3)
	result, err := h.service.UpdateApproval(context.Background(), domain.ApprovalAction{AppealID: id, ApprovalName: "b", Actor: "b@example.com", Action: "approve"})
	if result != nil || !errors.Is(err, appeal.ErrApprovalNotEligibleForAction) {
		t.Fatalf("expected bounded retry failure: %v", err)
	}
	h.mockProviderService.AssertNotCalled(t, "GrantAccess", mock.Anything, mock.Anything)
	h.mockNotifier.AssertNotCalled(t, "Notify", mock.Anything, mock.Anything)
}

func TestParallelRetryCannotApproveAReplacementRequestByStepName(t *testing.T) {
	h := newServiceTestHelper()
	defer h.assertExpectations(t)
	id := uuid.NewString()
	h.mockRepository.EXPECT().GetByID(mock.Anything, id).Return(completionSnapshot(id, false), nil).Once()
	replacement := completionSnapshot(id, true)
	replacement.Revision = 1
	for _, step := range replacement.Approvals {
		step.AppealRevision = 1
		step.ID = "new-" + step.ID
	}
	h.mockRepository.EXPECT().GetByID(mock.Anything, id).Return(replacement, nil).Once()
	h.mockRepository.EXPECT().UpdateWithLock(mock.Anything, id, (*domain.Grant)(nil), mock.Anything).RunAndReturn(func(ctx context.Context, id string, old *domain.Grant, mutate func(*domain.Appeal) error) (*domain.Appeal, error) {
		return nil, mutate(completionSnapshot(id, true))
	}).Once()
	_, err := h.service.UpdateApproval(context.Background(), domain.ApprovalAction{AppealID: id, ApprovalName: "B", Actor: "b@example.com", Action: "approve"})
	if !errors.Is(err, appeal.ErrApprovalNotEligibleForAction) {
		t.Fatalf("replacement request was not rejected: %v", err)
	}
	h.mockProviderService.AssertNotCalled(t, "GrantAccess", mock.Anything, mock.Anything)
}
