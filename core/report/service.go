package report

import (
	"context"
	"sort"
	"strings"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/plugins/notifiers"
)

//go:generate mockery --name=repository --exported --with-expecter
type repository interface {
	GetPendingApprovalsList(ctx context.Context, filters *PendingApprovalsReportFilter) ([]*PendingApprovalModel, error)
}

//go:generate mockery --name=notifier --exported --with-expecter
type notifier interface {
	notifiers.Client
}

type ServiceDeps struct {
	Repository repository
	Logger     log.Logger
	Notifier   notifier
}

type Service struct {
	repo     repository
	logger   log.Logger
	notifier notifier
}

func NewService(deps ServiceDeps) *Service {
	return &Service{
		deps.Repository,
		deps.Logger,
		deps.Notifier,
	}
}

type GetPendingApprovalsListConfig struct {
	DryRun bool
}

func (s *Service) GetPendingApprovalsList(ctx context.Context, cfg *GetPendingApprovalsListConfig) ([]*PendingApproval, error) {
	s.logger.Info(ctx, "retrieving pending approvals...")
	boolFalse := false
	pendingApprovals, err := s.repo.GetPendingApprovalsList(ctx, &PendingApprovalsReportFilter{
		ApprovalStatuses: []string{domain.ApprovalStatusPending},
		AppealStatuses:   []string{domain.AppealStatusPending},
		ApprovalStale:    &boolFalse,
	})
	if err != nil {
		s.logger.Error(ctx, "failed to retrieve pending approvals", "error", err.Error())
		return nil, err
	}
	s.logger.Info(ctx, "retrieved pending approvals", "count", len(pendingApprovals))

	approverPendingApprovalsMap := make(map[string][]PendingAppeal)
	seen := make(map[string]map[string]bool)
	for _, approval := range pendingApprovals {
		email := strings.ToLower(strings.TrimSpace(approval.Approver))
		if seen[email] == nil {
			seen[email] = map[string]bool{}
		}
		if seen[email][approval.AppealID] {
			continue
		}
		seen[email][approval.AppealID] = true
		approverPendingApprovalsMap[email] = append(approverPendingApprovalsMap[email], PendingAppeal{
			ID: approval.AppealID,
		})
	}

	var report []*PendingApproval
	var notifications []domain.Notification
	var recipients []string
	for recipient := range approverPendingApprovalsMap {
		recipients = append(recipients, recipient)
	}
	sort.Strings(recipients)
	for _, approver := range recipients {
		appeals := approverPendingApprovalsMap[approver]
		count := len(appeals)
		report = append(report, &PendingApproval{
			Approver: approver,
			Count:    count,
			Appeals:  appeals,
		})

		s.logger.Info(ctx, "preparing notification", "pending approvals count", count, "to", approver)
		notifications = append(notifications, domain.Notification{
			User: approver,
			Message: domain.NotificationMessage{
				Type: domain.NotificationTypePendingApprovalsReminder,
				Variables: map[string]interface{}{
					"approver":                approver,
					"pending_approvals_count": count,
				},
			},
		})
	}

	if !cfg.DryRun {
		sent, failed, skipped := 0, 0, 0
		for _, notification := range notifications {
			if errs := s.notifier.Notify(ctx, []domain.Notification{notification}); len(errs) > 0 {
				allSkipped := true
				for _, err := range errs {
					if _, isSkip := domain.NotificationSkipCode(err); !isSkip {
						allSkipped = false
					}
					notifiers.LogDeliveryError(ctx, s.logger, err)
				}
				if allSkipped {
					skipped++
				} else {
					failed++
				}
			} else {
				sent++
			}
		}
		s.logger.Info(ctx, "pending approvals reminder completed", "sent", sent, "skipped", skipped, "failed", failed)
	}

	return report, nil
}
