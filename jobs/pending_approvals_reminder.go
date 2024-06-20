package jobs

import (
	"context"
	"fmt"

	"github.com/goto/guardian/core/report"
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

	_, err := h.reportService.GetPendingApprovalsList(ctx, &report.GetPendingApprovalsListConfig{
		DryRun: c.DryRun,
	})
	if err != nil {
		h.logger.Info(ctx, "failed to retrieve pending approvals")
		return err
	}

	return nil
}
