package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/siren"
)

type BotExpirationAlertConfig struct {
	TargetBotEmails []string `mapstructure:"target_bot_emails"`
	ExpiringInDays  []int    `mapstructure:"expiring_in_days"`
	Severity        string   `mapstructure:"severity"`
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

	filters := domain.ListGrantsFilter{
		Statuses:           []string{string(domain.GrantStatusActive)},
		ExpiringInDays:     maxDays,
		ProviderTypes:      []string{"guardian"},
		AccountTypes:       []string{"bot"},
		WithPendingAppeal:  true,
		ExcludeEmptyAppeal: true,
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

		if len(cfg.TargetBotEmails) > 0 && !containsStr(cfg.TargetBotEmails, botEmail) {
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

		// Send generic notification to Siren for each group
		for _, group := range groups {
			severity := cfg.Severity
			if daysRemaining <= 1 {
				severity = "CRITICAL"
			}

			req := siren.NotificationRequest{
				Labels: map[string]string{
					"team_id":  group.ID,
					"severity": severity,
				},
				Template: "bot_access_expiry_template",
				Data: map[string]interface{}{
					"bot_email":     botEmail,
					"package_name":  g.Resource.Name,
					"team_name":     group.Name,
					"expiring_in":   fmt.Sprintf("%d days", daysRemaining),
					"expiration_dt": g.ExpirationDate.Format("2006-01-02"),
				},
			}

			if err := h.sirenClient.PostNotification(ctx, req); err != nil {
				h.logger.Error(ctx, "failed to post siren notification", "group", group.Name, "bot", botEmail, "error", err)
			} else {
				h.logger.Info(ctx, "Successfully dispatched siren notification", "group", group.Name, "bot", botEmail)
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

func containsStr(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

func containsInt(slice []int, val int) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
