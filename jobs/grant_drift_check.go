package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/goto/guardian/domain"
)

type GrantDriftCheckAlertingConfig struct {
	Enabled           bool   `mapstructure:"enabled"`
	AdminTeam         string `mapstructure:"admin_team"`
	OnFailureSeverity string `mapstructure:"on_failure_severity"`
	OnSuccessSeverity string `mapstructure:"on_success_severity"`
}

type GrantDriftCheckConfig struct {
	ProviderTypes []string                      `mapstructure:"provider_types"`
	BotAccountIDs []string                      `mapstructure:"bot_account_ids"`
	DryRun        bool                          `mapstructure:"dry_run"`
	Alerting      GrantDriftCheckAlertingConfig `mapstructure:"alerting"`
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
		ProviderTypes:     cfg.ProviderTypes,
		BotAccountIDs:     cfg.BotAccountIDs,
		DryRun:            cfg.DryRun,
		AlertingEnabled:   cfg.Alerting.Enabled,
		AdminTeam:         cfg.Alerting.AdminTeam,
		OnFailureSeverity: cfg.Alerting.OnFailureSeverity,
		OnSuccessSeverity: cfg.Alerting.OnSuccessSeverity,
	}

	start := time.Now()
	err := h.grantService.GrantDriftCheck(ctx, req)
	histGrantDriftCheckDuration.Record(ctx, float64(time.Since(start).Milliseconds()))
	return err
}
