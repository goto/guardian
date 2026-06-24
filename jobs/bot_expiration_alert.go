package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/siren"
)

const SIREN_TEMPLATE = "guardian_bot_access_expiry"

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

	// Base Filters from Config
	baseFilters := cfg.GrantFilters
	baseFilters.WithPendingAppeal = true
	baseFilters.ExcludeEmptyAppeal = true
	baseFilters.AccountTypes = []string{"bot"}
	if len(baseFilters.ProviderTypes) == 0 {
		baseFilters.ProviderTypes = []string{"guardian"}
	}

	// Fetch Upcoming Expirations (Active)
	activeFilters := baseFilters
	activeFilters.Statuses = []string{string(domain.GrantStatusActive)}
	activeFilters.ExpiringInDays = maxDays

	activeGrants, err := h.grantService.List(ctx, activeFilters)
	if err != nil {
		h.logger.Error(ctx, "failed to retrieve active expiring bot grants", "error", err)
		return err
	}

	// Fetch Recently Expired (Inactive)
	inactiveFilters := baseFilters
	inactiveFilters.Statuses = []string{string(domain.GrantStatusInactive)}

	inactiveGrants, err := h.grantService.List(ctx, inactiveFilters)
	if err != nil {
		h.logger.Error(ctx, "failed to retrieve inactive bot grants", "error", err)
		return err
	}

	var allGrants []domain.Grant
	allGrants = append(allGrants, activeGrants...)
	allGrants = append(allGrants, inactiveGrants...)

	now := time.Now()
	currentDate := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	for _, g := range allGrants {
		if g.ExpirationDate == nil {
			continue
		}

		// Strictly calculate the exact days remaining
		expDate := time.Date(g.ExpirationDate.Year(), g.ExpirationDate.Month(), g.ExpirationDate.Day(), 0, 0, 0, 0, time.UTC)
		daysRemaining := int(expDate.Sub(currentDate).Hours() / 24)

		isReminderDay := containsInt(cfg.ReminderInDays, daysRemaining)
		isExpiredDay := daysRemaining == 0 || daysRemaining == -1

		if !isReminderDay && !isExpiredDay {
			continue
		}

		botEmail := extractBotEmail(g)
		if botEmail == "" {
			continue
		}
		shieldUser, err := h.shieldClient.GetUser(ctx, botEmail)
		if err != nil {
			h.logger.Error(ctx, "failed to get shield user for bot", "bot_email", botEmail, "error", err)
			continue
		}
		groups, err := h.shieldClient.GetUserGroups(ctx, shieldUser.ID)
		if err != nil {
			h.logger.Error(ctx, "failed to get shield groups for bot", "bot_uuid", shieldUser.ID, "error", err)
			continue
		}

		isAlreadyExpired := now.After(*g.ExpirationDate) || string(g.Status) == string(domain.GrantStatusInactive)
		expiringInStr := fmt.Sprintf("%d days", daysRemaining)
		if daysRemaining < 0 {
			expiringInStr = fmt.Sprintf("already expired (%d days ago)", -daysRemaining)
		} else if daysRemaining == 0 {
			if isAlreadyExpired {
				expiringInStr = "already expired (Earlier Today)"
			} else {
				expiringInStr = "0 days (Later Today)"
			}
		}

		// Send notifications for each group the bot belongs to
		for _, group := range groups {
			teamSlug := group.Slug

			baseData := map[string]interface{}{
				"environment":   cfg.Environment,
				"bot_email":     botEmail,
				"package_name":  g.Resource.Name,
				"team_name":     group.Name,
				"expiring_in":   expiringInStr,
				"expiration_dt": g.ExpirationDate.Format("2006-01-02"),
				"appeal_id":     g.AppealID,
				"is_expired":    isAlreadyExpired,
			}

			severity := "WARNING"
			if daysRemaining <= cfg.CriticalThresholdInDays || isExpiredDay {
				severity = "CRITICAL"
			}

			environment := cfg.Environment
			if environment == "" {
				environment = "production"
			}

			notification := siren.NotificationRequest{
				Template: SIREN_TEMPLATE,
				Labels: map[string]string{
					"environment": environment,
					"severity":    severity,
					"team":        teamSlug,
				},
				Data: baseData,
			}

			if err := h.sirenClient.PostNotification(ctx, notification); err != nil {
				h.logger.Error(ctx, "failed to post siren notification",
					"team", teamSlug,
					"environment", environment,
					"labels", notification.Labels,
					"error", err,
				)
			} else {
				h.logger.Info(ctx, "successfully dispatched siren notification",
					"team", teamSlug,
					"labels", notification.Labels,
				)
			}
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
