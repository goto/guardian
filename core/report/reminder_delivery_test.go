package report

import (
	"context"
	"errors"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
)

type reminderRepo struct{}

func (r *reminderRepo) GetPendingApprovalsList(context.Context, *PendingApprovalsReportFilter) ([]*PendingApprovalModel, error) {
	return []*PendingApprovalModel{{AppealID: "one", Approver: "A@example.com"}, {AppealID: "one", Approver: "a@example.com"}, {AppealID: "two", Approver: "b@example.com"}}, nil
}

type reminderNotifier struct{ calls []string }

func (n *reminderNotifier) Notify(_ context.Context, items []domain.Notification) []error {
	for _, item := range items {
		n.calls = append(n.calls, item.User)
		if item.User == "a@example.com" {
			return []error{errors.New("synthetic failure")}
		}
	}
	return nil
}
func TestReminderDeduplicatesRequestsWithoutFailingBatch(t *testing.T) {
	r := &reminderRepo{}
	n := &reminderNotifier{}
	s := NewService(ServiceDeps{Repository: r, Notifier: n, Logger: log.NewNoop()})
	for i := 0; i < 1; i++ {
		rows, err := s.GetPendingApprovalsList(context.Background(), &GetPendingApprovalsListConfig{})
		if err != nil || len(rows) != 2 || rows[0].Count != 1 {
			t.Fatalf("wrong report/error: %+v %v", rows, err)
		}
	}
	if len(n.calls) != 2 {
		t.Fatalf("failed recipient prevented other sends: %+v", n.calls)
	}
}
func TestReminderDryRunDoesNotSend(t *testing.T) {
	r := &reminderRepo{}
	n := &reminderNotifier{}
	s := NewService(ServiceDeps{Repository: r, Notifier: n, Logger: log.NewNoop()})
	_, err := s.GetPendingApprovalsList(context.Background(), &GetPendingApprovalsListConfig{DryRun: true})
	if err != nil || len(n.calls) > 0 {
		t.Fatal("dry run sent")
	}
}
