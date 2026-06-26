package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/plugins/notifiers/alertmanager"
)

type BotExpirationAlertConfig struct {
	// Pre-fetch DB filters (allows passing account_ids, provider_types, etc., from config)
	GrantFilters            domain.ListGrantsFilter `mapstructure:"filters"`
	ReminderInDays          []int                   `mapstructure:"reminder_in_days"`
	CriticalThresholdInDays int                     `mapstructure:"critical_threshold_in_days"`
	Environment             string                  `mapstructure:"environment"`
}

func (h *handler) BotExpirationAlert(ctx context.Context, rawCfg Config) error {
	h.logger.Info(ctx, "running bot expiration alert job")

	var cfg BotExpirationAlertConfig
	if err := rawCfg.Decode(&cfg); err != nil {
		return fmt.Errorf("invalid job config: %w", err)
	}

	if len(cfg.ReminderInDays) == 0 {
		h.logger.Warn(ctx, "no reminder_in_days configured, skipping job")
		return nil
	}

	// Find the maximum threshold to fetch grants only once
	maxDays := 0
	for _, days := range cfg.ReminderInDays {
		if days > maxDays {
			maxDays = days
		}
	}

	filters := cfg.GrantFilters

	// Strictly fetch Active grants for upcoming expirations
	filters.Statuses = []string{string(domain.GrantStatusActive)}
	filters.ExpiringInDays = maxDays
	filters.WithPendingAppeal = true
	filters.ExcludeEmptyAppeal = true
	falseBool := false
	filters.IsPermanent = &falseBool

	if len(filters.AccountTypes) == 0 {
		filters.AccountTypes = []string{"bot"}
	}
	if len(filters.ProviderTypes) == 0 {
		filters.ProviderTypes = []string{"guardian"}
	}

	grants, err := h.grantService.List(ctx, filters)
	if err != nil {
		h.logger.Error(ctx, "failed to retrieve active expiring bot grants", "error", err)
		return err
	}

	now := time.Now()
	currentDate := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	for _, g := range grants {
		if g.ExpirationDate == nil {
			continue
		}

		// Strictly calculate the exact days remaining
		expDate := time.Date(g.ExpirationDate.Year(), g.ExpirationDate.Month(), g.ExpirationDate.Day(), 0, 0, 0, 0, time.UTC)
		daysRemaining := int(expDate.Sub(currentDate).Hours() / 24)

		isReminderDay := containsInt(cfg.ReminderInDays, daysRemaining)
		isDayZero := daysRemaining == 0

		// Skip if it's not a reminder day AND it's not expiring exactly today
		if !isReminderDay && !isDayZero {
			continue
		}

		botEmail := extractBotEmail(g)
		if botEmail == "" {
			continue
		}

		teams, err := h.userManagement.GetUserGroups(ctx, botEmail)
		if err != nil {
			h.logger.Error(ctx, "failed to resolve teams for bot", "bot_email", botEmail, "error", err)
			continue
		}

		expiringInStr := fmt.Sprintf("%d days", daysRemaining)
		if isDayZero {
			expiringInStr = "0 days (Today)"
		}

		severity := "WARNING"
		// Automatically bump to CRITICAL if it hits the threshold OR if it expires today
		if daysRemaining <= cfg.CriticalThresholdInDays || isDayZero {
			severity = "CRITICAL"
		}

		environment := cfg.Environment
		if environment == "" {
			environment = "production"
		}

		for _, team := range teams {
			event := alertmanager.Event{
				Title:    alertmanager.BotExpirationAlertEvent,
				Severity: severity,
				Team:     team.Slug,
				Data: map[string]interface{}{
					"environment":   environment,
					"bot_email":     botEmail,
					"package_name":  g.Resource.Name,
					"team_name":     team.Slug,
					"expiring_in":   expiringInStr,
					"expiration_dt": g.ExpirationDate.Format("2006-01-02"),
					"appeal_id":     g.AppealID,
				},
			}

			err := h.alertManager.Send(ctx, event)
			if err != nil {
				h.logger.Error(ctx, "failed to dispatch bot expiration notifications",
					"bot_email", botEmail,
					"error", err)
				return err
			}
			h.logger.Info(ctx, "successfully dispatched bot expiration notifications")
		}
	}

	return nil
}

func extractBotEmail(g domain.Grant) string {
	if g.Appeal != nil && g.Appeal.Details != nil {
		if policyMeta, ok := g.Appeal.Details["__policy_metadata"].(map[string]interface{}); ok {
			if ramDetails, ok := policyMeta["ram_user_details"].(map[string]interface{}); ok {
				if email, ok := ramDetails["user_principal_name"].(string); ok {
					return email
				}
			}
		}
	}
	return ""
}

func containsInt(slice []int, val int) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
