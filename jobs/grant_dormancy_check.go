package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/goto/guardian/domain"
)

type GrantDormancyCheckConfig struct {
	DryRun         bool          `mapstructure:"dry_run"`
	StartDate      time.Time     `mapstructure:"start_date"`
	EndDate        time.Time     `mapstructure:"end_date"`
	RetainGrantFor time.Duration `mapstructure:"retain_grant_for"`
}

func (h *handler) GrantDormancyCheck(ctx context.Context, c Config) error {
	var cfg GrantDormancyCheckConfig
	if err := c.Decode(&cfg); err != nil {
		return fmt.Errorf("invalid config for %s job: %w", TypeRevokeGrantsByUserCriteria, err)
	}

	providers, err := h.providerService.Find(ctx)
	if err != nil {
		return fmt.Errorf("listing providers: %w", err)
	}

	for _, p := range providers {
		h.logger.Info(fmt.Sprintf("checking dormancy for grants under provider: %q", p.URN))
		if err := h.grantService.DormancyCheck(ctx, domain.DormancyCheckCriteria{
			ProviderID:     p.ID,
			TimestampeGte:  cfg.StartDate,
			TimestampeLte:  cfg.EndDate,
			RetainDuration: cfg.RetainGrantFor,
			DryRun:         cfg.DryRun,
		}); err != nil {
			h.logger.Error(fmt.Sprintf("failed to check dormancy for provider %q", p.URN), "error", err)
		}
	}

	return nil
}
