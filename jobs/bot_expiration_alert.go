package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/evaluator"
	"github.com/goto/guardian/plugins/identities"
	"github.com/goto/guardian/plugins/notifiers/alertmanager"
)

const defaultExtractBotEmailExpr evaluator.Expression = "$grant?.appeal?.details?.__policy_metadata?.ram_user_details?.user_principal_name"

type BotExpirationAlertConfig struct {
	// Pre-fetch DB filters (allows passing account_ids, provider_types, etc., from config)
	GrantFilters            domain.ListGrantsFilter `mapstructure:"filters"`
	IAM                     domain.IAMConfig        `mapstructure:"iam"`
	ExtractBotEmail         evaluator.Expression    `mapstructure:"extract_bot_email"`
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
	if cfg.ExtractBotEmail == "" {
		cfg.ExtractBotEmail = defaultExtractBotEmailExpr
	}

	iamManager := identities.NewManager(h.crypto, h.validator)
	iamConfig, err := iamManager.ParseConfig(&cfg.IAM)
	if err != nil {
		return fmt.Errorf("parsing IAM config: %w", err)
	}
	iamClient, err := iamManager.GetClient(iamConfig)
	if err != nil {
		return fmt.Errorf("initializing IAM client: %w", err)
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
	if len(grants) == 0 {
		h.logger.Info(ctx, "no expiring bot grants found")
		return nil
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
		h.logger.Info(ctx, "process alert", "account_id", g.AccountID, "expiration_date", g.ExpirationDate)

		botEmail, err := h.evaluateBotEmail(cfg.ExtractBotEmail, g)
		if err != nil {
			h.logger.Error(ctx, "failed to evaluate extract_bot_email", "grant_id", g.ID, "expression", cfg.ExtractBotEmail.String(), "error", err)
			continue
		}

		userDetails, err := iamClient.GetUser(botEmail)
		if err != nil {
			h.logger.Error(ctx, "failed to fetch user details", "bot_email", botEmail, "error", err)
			continue
		}
		userID, err := extractUserID(userDetails)
		if err != nil {
			h.logger.Error(ctx, "failed to extract user id", "bot_email", botEmail, "error", err)
			continue
		}

		userGroups, err := iamClient.GetUserGroups(userID)
		if err != nil {
			h.logger.Error(ctx, "failed to resolve teams for bot", "bot_email", botEmail, "user_id", userID, "error", err)
			continue
		}
		teams, err := extractGroups(userGroups)
		if err != nil {
			h.logger.Error(ctx, "failed to parse user groups", "bot_email", botEmail, "user_id", userID, "error", err)
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
			teamName := team.Slug
			if teamName == "" {
				teamName = team.Name
			}
			if teamName == "" {
				teamName = team.ID
			}
			if teamName == "" {
				continue
			}

			packageName := ""
			if g.Resource != nil {
				packageName = g.Resource.Name
			}

			event := alertmanager.Event{
				Title:    alertmanager.BotExpirationAlertEvent,
				Severity: severity,
				Team:     teamName,
				Data: map[string]interface{}{
					"environment":   environment,
					"bot_email":     botEmail,
					"package_name":  packageName,
					"team_name":     teamName,
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

func (h *handler) evaluateBotEmail(expr evaluator.Expression, grant domain.Grant) (string, error) {
	grantMap, err := grantToMap(grant)
	if err != nil {
		return "", fmt.Errorf("parsing grant details: %w", err)
	}
	evaluated, err := expr.EvaluateWithVars(map[string]interface{}{
		"grant": grantMap,
	})
	if err != nil {
		return "", fmt.Errorf("evaluating extract_bot_email: %w", err)
	}

	botEmail, ok := evaluated.(string)
	if !ok {
		return "", fmt.Errorf("invalid type for extract_bot_email evaluation result: expected string, got %T; value is %q", evaluated, evaluated)
	}
	if botEmail == "" {
		return "", fmt.Errorf("invalid value for extract_bot_email evaluation result: expected non-empty string")
	}
	if err := h.validator.Var(botEmail, "email"); err != nil {
		return "", fmt.Errorf("invalid value for extract_bot_email evaluation result: expected a valid email address, got %q", botEmail)
	}
	return botEmail, nil
}

func grantToMap(grant domain.Grant) (map[string]interface{}, error) {
	var grantMap map[string]interface{}
	payload, err := json.Marshal(grant)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(payload, &grantMap); err != nil {
		return nil, err
	}
	return grantMap, nil
}

func extractUserID(userDetails interface{}) (string, error) {
	userDetailsMap, ok := userDetails.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("parsing user details: expected map[string]interface{}, got %T", userDetails)
	}

	switch userData := userDetailsMap["user"].(type) {
	case domain.User:
		if userData.ID == "" {
			return "", fmt.Errorf("parsing user details: expected non-empty user.id in response")
		}
		return userData.ID, nil
	case map[string]interface{}:
		userID, ok := userData["id"].(string)
		if !ok || userID == "" {
			return "", fmt.Errorf("parsing user details: expected non-empty user.id in response")
		}
		return userID, nil
	default:
		return "", fmt.Errorf("parsing user details: expected user object in response, got %T", userData)
	}
}

func extractGroups(userGroups interface{}) ([]domain.Group, error) {
	switch groups := userGroups.(type) {
	case []domain.Group:
		return groups, nil
	case map[string]interface{}:
		rawGroups, ok := groups["groups"]
		if !ok {
			return nil, fmt.Errorf("parsing user groups: expected groups field in response")
		}
		return extractGroups(rawGroups)
	case []interface{}:
		parsed := make([]domain.Group, 0, len(groups))
		for _, item := range groups {
			groupMap, ok := item.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("parsing user groups: expected group object, got %T", item)
			}
			parsed = append(parsed, domain.Group{
				ID:   toString(groupMap["id"]),
				Name: toString(groupMap["name"]),
				Slug: toString(groupMap["slug"]),
			})
		}
		return parsed, nil
	default:
		return nil, fmt.Errorf("parsing user groups: unsupported response type %T", userGroups)
	}
}

// toString return empty string if v is nil
func toString(v interface{}) string {
	s, _ := v.(string)
	return s
}

func containsInt(slice []int, val int) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
