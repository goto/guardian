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

type skippedReminderNotifier struct{ calls int }

func (n *skippedReminderNotifier) Notify(_ context.Context, items []domain.Notification) []error {
	n.calls++
	if items[0].User == "a@example.com" {
		return []error{&domain.NotificationSkippedError{Code: domain.NotificationRecipientNotResolved}}
	}
	return nil
}

type reminderSummaryLogger struct {
	log.Logger
	summary       map[string]interface{}
	warns, errors int
}

func (l *reminderSummaryLogger) Warn(context.Context, string, ...interface{})  { l.warns++ }
func (l *reminderSummaryLogger) Error(context.Context, string, ...interface{}) { l.errors++ }
func (l *reminderSummaryLogger) Info(_ context.Context, msg string, args ...interface{}) {
	if msg != "pending approvals reminder completed" {
		return
	}
	l.summary = map[string]interface{}{}
	for i := 0; i+1 < len(args); i += 2 {
		l.summary[args[i].(string)] = args[i+1]
	}
}
func TestReminderCountsExpectedNonDeliveryAsSkipped(t *testing.T) {
	n := &skippedReminderNotifier{}
	l := &reminderSummaryLogger{Logger: log.NewNoop()}
	s := NewService(ServiceDeps{Repository: &reminderRepo{}, Notifier: n, Logger: l})
	_, err := s.GetPendingApprovalsList(context.Background(), &GetPendingApprovalsListConfig{})
	if err != nil || n.calls != 2 {
		t.Fatalf("skip blocked reminder job: %v", err)
	}
	if l.warns != 1 || l.errors != 0 || l.summary["sent"] != 1 || l.summary["skipped"] != 1 || l.summary["failed"] != 0 {
		t.Fatalf("incorrect job outcome: %+v", l)
	}
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
