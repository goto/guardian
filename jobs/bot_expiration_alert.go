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
	GrantFilters   domain.ListGrantsFilter `mapstructure:"filters"`
	ExpiringInDays []int                   `mapstructure:"expiring_in_days"`
	Severity       string                  `mapstructure:"severity"`
	Environment    string                  `mapstructure:"environment"`
}

func (h *handler) BotExpirationAlert(ctx context.Context, rawCfg Config) error {
	h.logger.Info(ctx, "running bot expiration alert job")

	var cfg BotExpirationAlertConfig
	if err := rawCfg.Decode(&cfg); err != nil {
		return fmt.Errorf("invalid job config: %w", err)
	}

	if len(cfg.ExpiringInDays) == 0 {
		h.logger.Warn(ctx, "no expiring_in_days configured, skipping job")
		return nil
	}

	// Find the maximum threshold to fetch grants only once
	maxDays := 0
	for _, days := range cfg.ExpiringInDays {
		if days > maxDays {
			maxDays = days
		}
	}

	filters := cfg.GrantFilters

	// Force mandatory fields required for this job to function safely
	filters.Statuses = []string{string(domain.GrantStatusActive)}
	filters.ExpiringInDays = maxDays
	filters.WithPendingAppeal = true
	filters.ExcludeEmptyAppeal = true
	filters.AccountTypes = []string{"bot"}

	// Apply defaults only if the user didn't explicitly override them in the config
	if len(filters.ProviderTypes) == 0 {
		filters.ProviderTypes = []string{"guardian"}
	}

	grants, err := h.grantService.List(ctx, filters)
	if err != nil {
		h.logger.Error(ctx, "failed to retrieve active expiring bot grants", "error", err)
		return err
	}

	now := time.Now()
	// Normalize current time to midnight UTC to ensure accurate day-difference calculation
	currentDate := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	for _, g := range grants {
		if g.ExpirationDate == nil {
			continue
		}

		// Strictly calculate the exact days remaining
		expDate := time.Date(g.ExpirationDate.Year(), g.ExpirationDate.Month(), g.ExpirationDate.Day(), 0, 0, 0, 0, time.UTC)
		daysRemaining := int(expDate.Sub(currentDate).Hours() / 24)

		// Skip if the exact days remaining are not in our target array (e.g. 7, 3, 1)
		if !containsInt(cfg.ExpiringInDays, daysRemaining) {
			continue
		}

		botEmail := extractBotEmail(g)
		if botEmail == "" {
			continue
		}
		// Fetch the Shield User using the extracted email
		shieldUser, err := h.shieldClient.GetUser(ctx, botEmail)
		if err != nil {
			h.logger.Error(ctx, "failed to get shield user for bot", "bot_email", botEmail, "error", err)
			continue
		}
		// Fetch the groups that the bot belongs to using its Shield UUID
		groups, err := h.shieldClient.GetUserGroups(ctx, shieldUser.ID)
		if err != nil {
			h.logger.Error(ctx, "failed to get shield groups for bot", "bot_uuid", shieldUser.ID, "error", err)
			continue
		}

		// Send notifications for each group the bot belongs to
		for _, group := range groups {
			teamSlug := group.Slug

			// Construct the base data payload (used across all notifications)
			baseData := map[string]interface{}{
				"environment":   cfg.Environment,
				"bot_email":     botEmail,
				"package_name":  g.Resource.Name,
				"team_name":     group.Name,
				"expiring_in":   fmt.Sprintf("%d days", daysRemaining),
				"expiration_dt": g.ExpirationDate.Format("2006-01-02"),
				"appeal_id":     g.AppealID,
			}

			severity := cfg.Severity
			if severity == "" {
				severity = "WARNING"
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
					"environment", cfg.Environment,
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

// Helper function to extract email from a nested appeal map
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
