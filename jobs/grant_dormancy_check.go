package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/goto/guardian/domain"
)

type GrantDormancyCheckConfig struct {
	DryRun         bool   `mapstructure:"dry_run"`
	StartDate      string `mapstructure:"start_date"`
	EndDate        string `mapstructure:"end_date"`
	RetainGrantFor string `mapstructure:"retain_grant_for"`
}

func (h *handler) GrantDormancyCheck(ctx context.Context, c Config) error {
	var cfg GrantDormancyCheckConfig
	if err := c.Decode(&cfg); err != nil {
		return fmt.Errorf("invalid config for %s job: %w", TypeRevokeGrantsByUserCriteria, err)
	}

	startDate, err := time.Parse(time.RFC3339, cfg.StartDate)
	if err != nil {
		return fmt.Errorf("invalid start date: %w", err)
	}
	endDate, err := time.Parse(time.RFC3339, cfg.EndDate)
	if err != nil {
		return fmt.Errorf("invalid end date: %w", err)
	}
	retainGrantFor, err := time.ParseDuration(cfg.RetainGrantFor)
	if err != nil {
		return fmt.Errorf("invalid retain grant for duration: %w", err)
	}

	providers, err := h.providerService.Find(ctx)
	if err != nil {
		return fmt.Errorf("listing providers: %w", err)
	}

	for _, p := range providers {
		h.logger.Info(fmt.Sprintf("checking dormancy for grants under provider: %q", p.URN))
		if err := h.grantService.DormancyCheck(ctx, domain.DormancyCheckCriteria{
			ProviderID:     p.ID,
			TimestampeGte:  startDate,
			TimestampeLte:  endDate,
			RetainDuration: retainGrantFor,
			DryRun:         cfg.DryRun,
		}); err != nil {
			h.logger.Error(fmt.Sprintf("failed to check dormancy for provider %q", p.URN), "error", err)
		}
	}

	return nil
}
