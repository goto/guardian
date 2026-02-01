package report

import (
	"context"
	"time"

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
	for _, approval := range pendingApprovals {
		approverPendingApprovalsMap[approval.Approver] = append(approverPendingApprovalsMap[approval.Approver], PendingAppeal{
			ID: approval.AppealID,
		})
	}

	var report []*PendingApproval
	for approver, appeals := range approverPendingApprovalsMap {
		count := len(appeals)
		report = append(report, &PendingApproval{
			Approver: approver,
			Count:    count,
			Appeals:  appeals,
		})

		s.logger.Info(ctx, "preparing notification", "pending approvals count", count, "to", approver)
		notification := domain.Notification{
			User: approver,
			Message: domain.NotificationMessage{
				Type: domain.NotificationTypePendingApprovalsReminder,
				Variables: map[string]interface{}{
					"approver":                approver,
					"pending_approvals_count": count,
				},
			},
		}
		if !cfg.DryRun {
			if errs := s.notifier.Notify(ctx, []domain.Notification{notification}); errs != nil {
				for _, e := range errs {
					s.logger.Error(ctx, "failed to send notifications", "error", e.Error())
				}
				s.logger.Info(ctx, "pending approvals notifications sent")
			}
			time.Sleep(time.Second)
		}
	}

	return report, nil
}
