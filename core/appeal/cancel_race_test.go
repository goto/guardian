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

func TestCancellationRevalidatesLockedState(t *testing.T) {
	for _, state := range []string{"pending", "approved", "rejected", "canceled", "revised"} {
		t.Run(state, func(t *testing.T) {
			h := newServiceTestHelper()
			defer h.assertExpectations(t)
			id := uuid.NewString()
			initial := serviceParallelAppeal(id)
			fresh := serviceParallelAppeal(id)
			fresh.Status = state
			if state == "revised" {
				fresh.Status = "pending"
				fresh.Revision++
			}
			h.mockRepository.EXPECT().GetByID(mock.Anything, id).Return(initial, nil).Once()
			h.mockRepository.EXPECT().UpdateWithLock(mock.Anything, id, (*domain.Grant)(nil), mock.Anything).RunAndReturn(func(ctx context.Context, id string, old *domain.Grant, mutate func(*domain.Appeal) error) (*domain.Appeal, error) {
				if err := mutate(fresh); err != nil {
					return nil, err
				}
				return fresh, nil
			}).Once()
			if state == "pending" {
				h.mockAuditLogger.EXPECT().Log(mock.Anything, appeal.AuditKeyCancel, mock.Anything).Return(nil).Once()
			}
			result, err := h.service.Cancel(context.Background(), id)
			if state == "pending" {
				if err != nil || result.Status != "canceled" {
					t.Fatalf("cancel failed: %v", err)
				}
			} else if state == "revised" {
				if !errors.Is(err, appeal.ErrApprovalNotEligibleForAction) || fresh.Revision != 2 || fresh.Status != "pending" {
					t.Fatal("replacement request was canceled")
				}
			} else if !errors.Is(err, appeal.ErrAppealNotEligibleForApproval) || fresh.Status != state {
				t.Fatalf("terminal state overwritten: %s %v", fresh.Status, err)
			}
			h.mockRepository.AssertNotCalled(t, "Update", mock.Anything, mock.Anything)
		})
	}
}
