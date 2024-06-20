package jobs

import (
	"context"
	"fmt"

	"github.com/goto/guardian/core/report"
	"github.com/goto/guardian/domain"
)

type PendingApprovalsReminderConfig struct {
	DryRun bool `mapstructure:"dry_run"`
}

func (h *handler) PendingApprovalsReminder(ctx context.Context, cfg Config) error {
	h.logger.Info(ctx, fmt.Sprintf("starting %q job", TypePendingApprovalsReminder))
	defer h.logger.Info(ctx, fmt.Sprintf("finished %q job", TypePendingApprovalsReminder))

	var c PendingApprovalsReminderConfig
	if err := cfg.Decode(&c); err != nil {
		return fmt.Errorf("invalid config for %s job: %w", TypePendingApprovalsReminder, err)
	}

	h.logger.Info(ctx, "retrieving pending approvals...")
	pendingApprovals, err := h.reportService.GetPendingApprovalsList(ctx, &report.PendingApprovalsReportFilter{
		ApprovalStatuses: []string{domain.ApprovalStatusPending},
		AppealStatuses:   []string{domain.AppealStatusPending},
	})
	if err != nil {
		h.logger.Info(ctx, "failed to retrieve pending approvals")
		return err
	}
	h.logger.Info(ctx, "retrieved pending approvals", "count", len(pendingApprovals))

	approverPendingApprovalsMap := make(map[string][]*report.PendingApprovalsReport)
	for _, approval := range pendingApprovals {
		approverPendingApprovalsMap[approval.Approver] = append(approverPendingApprovalsMap[approval.Approver], approval)
	}

	var notifications []domain.Notification
	for k, v := range approverPendingApprovalsMap {
		h.logger.Info(ctx, "preparing notification", "pending approvals count", len(v), "to", k)
		notifications = append(notifications, domain.Notification{
			User: k,
			Message: domain.NotificationMessage{
				Type: domain.NotificationTypePendingApprovalsReminder,
				Variables: map[string]interface{}{
					"pending_approvals_count": len(v),
				},
			},
		})
	}

	if !c.DryRun {
		if errs := h.notifier.Notify(ctx, notifications); errs != nil {
			for _, e := range errs {
				h.logger.Error(ctx, "failed to send notifications", "error", e)
			}
			h.logger.Info(ctx, "pending approvals notifications sent")
		}
	}

	return nil
}
