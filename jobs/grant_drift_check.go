package jobs

import (
	"context"
	"fmt"

	"github.com/goto/guardian/domain"
)

type GrantDriftCheckConfig struct {
	ProviderTypes []string `mapstructure:"provider_types"`
	BotAccountIDs []string `mapstructure:"bot_account_ids"`
	AdminTeam     string   `mapstructure:"admin_team"`
	DryRun        bool     `mapstructure:"dry_run"`
}

func (h *handler) GrantDriftCheck(ctx context.Context, c Config) error {
	h.logger.Info(ctx, "running grant drift check job")

	var cfg GrantDriftCheckConfig
	if err := c.Decode(&cfg); err != nil {
		return fmt.Errorf("invalid config for %s job: %w", TypeGrantDriftCheck, err)
	}

	if cfg.DryRun {
		h.logger.Info(ctx, "dry run enabled: drift detection will run but no PD alerts will be sent")
	}

	req := domain.GrantDriftCheckRequest{
		ProviderTypes: cfg.ProviderTypes,
		BotAccountIDs: cfg.BotAccountIDs,
		AdminTeam:     cfg.AdminTeam,
		DryRun:        cfg.DryRun,
	}

	return h.grantService.GrantDriftCheck(ctx, req)
}
