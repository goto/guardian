package jobs

import (
	"context"

	"github.com/goto/guardian/core/report"
	"github.com/goto/guardian/domain"
)

func (h *handler) PendingApprovalsReminder(ctx context.Context, cfg Config) error {
	h.logger.Info(ctx, "running pending approvals reminder job")

	h.logger.Info(ctx, "retrieving pending approvals...")
	pendingApprovals, err := h.reportService.GetPendingApprovalsList(ctx, report.ReportFilter{
		ApprovalStatuses: []string{domain.ApprovalStatusPending},
		AppealStatuses:   []string{domain.AppealStatusPending, domain.AppealStatusCanceled},
	})
	if err != nil {
		h.logger.Info(ctx, "failed to retrieve pending approvals")
		return err
	}
	h.logger.Info(ctx, "retrieved pending approvals", "count", len(pendingApprovals))

	approverPendingApprovalsMap := make(map[string][]report.Report)
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

	if errs := h.notifier.Notify(ctx, notifications); errs != nil {
		for _, e := range errs {
			h.logger.Error(ctx, "failed to send notifications", "error", e)
		}
	}

	h.logger.Info(ctx, "pending approvals notifications sent")
	return nil
}
