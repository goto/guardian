package alertmanager

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
)

type Config struct {
	AdminRoutingKey string `mapstructure:"admin_routing_key"`
}

type AlertManager struct {
	config Config
	pd     PDSender
	logger log.Logger
}

func New(config Config, pdClient PDSender, logger log.Logger) *AlertManager {
	return &AlertManager{
		config: config,
		pd:     pdClient,
		logger: logger,
	}
}

// NotifyDriftCheck sends a single PagerDuty summary alert to adminTeam listing all drifted
// dedup_key: drift-check:admin:{hash(sorted accountIDs)}
func (m *AlertManager) NotifyDriftCheck(ctx context.Context, adminTeam string, issues []domain.GrantDriftIssue) []error {
	totalDrifted := 0
	totalFailures := 0
	totalNotApplicable := 0
	allAccountIDs := []string{}
	details := []map[string]interface{}{}

	for _, issue := range issues {
		d := map[string]interface{}{
			"account_id":   issue.AccountID,
			"account_type": issue.Grant.AccountType,
			"grant_id":     issue.Grant.ID,
			"role":         issue.Grant.Role,
		}
		if issue.Grant.Resource != nil {
			d["resource"] = fmt.Sprintf("%s (%s: %s)",
				issue.Grant.Resource.Name,
				issue.Grant.Resource.ProviderType,
				issue.Grant.Resource.URN)
		}
		if issue.Grant.ExpirationDate != nil {
			d["expiration_date"] = issue.Grant.ExpirationDate.Format("Jan 02, 2006 15:04:05 UTC")
		}
		switch {
		case issue.RemediationNotApplicable:
			d["remediation_status"] = "not_applicable"
			totalNotApplicable++
		case issue.RemediationError != "":
			d["remediation_status"] = "failed"
			d["remediation_error"] = issue.RemediationError
			totalFailures++
		default:
			d["remediation_status"] = "recreated"
		}
		allAccountIDs = append(allAccountIDs, issue.AccountID)
		details = append(details, d)
	}

	totalDrifted += len(issues)

	dedupKey := fmt.Sprintf("drift-check:admin:%s", hashAccountIDs(allAccountIDs))

	severity := severityWarning
	if totalFailures > 0 {
		severity = severityCritical
	}

	recreated := totalDrifted - totalFailures - totalNotApplicable
	summary := fmt.Sprintf("Guardian: %d drifted grant(s) across %d team(s) (%d recreated, %d failed, %d not_applicable)",
		totalDrifted, len(issues), recreated, totalFailures, totalNotApplicable)

	event := Event{
		RoutingKey:  m.config.AdminRoutingKey,
		DedupKey:    dedupKey,
		EventAction: eventActionTrigger,
		Summary:     summary,
		Source:      "guardian",
		Severity:    severity,
		CustomDetails: map[string]interface{}{
			"total_drifted":              totalDrifted,
			"remediation_failures":       totalFailures,
			"remediation_not_applicable": totalNotApplicable,
			"grants":                     details,
		},
	}

	if err := m.pd.Send(ctx, event); err != nil {
		m.logger.Error(ctx, "failed to trigger drift check alert", "admin_team", adminTeam, "error", err)
		return []error{err}
	}

	m.logger.Info(ctx, "pagerduty drift-check alert triggered", "admin_team", adminTeam, "dedup_key", dedupKey)
	return nil
}

func hashAccountIDs(accountIDs []string) string {
	sorted := make([]string, len(accountIDs))
	copy(sorted, accountIDs)
	sort.Strings(sorted)
	joined := strings.Join(sorted, ",")
	h := sha256.Sum256([]byte(joined))
	return fmt.Sprintf("%x", h[:6])
}
