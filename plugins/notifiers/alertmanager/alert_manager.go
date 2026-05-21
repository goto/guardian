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

type accountGroup struct {
	grants []map[string]interface{}
}

type AlertManager struct {
	pd     PDSender
	logger log.Logger
}

func New(pdClient PDSender, logger log.Logger) *AlertManager {
	return &AlertManager{
		pd:     pdClient,
		logger: logger,
	}
}

// NotifyDriftCheck sends a single PagerDuty summary alert to adminTeam listing all drifted
// dedup_key: drift-check:admin:{hash(sorted accountIDs)}
func (m *AlertManager) NotifyDriftCheck(ctx context.Context, adminTeamKey string, issues []domain.GrantDriftIssue) []error {
	totalFailures := 0
	totalNotApplicable := 0

	grouped := make(map[string]*accountGroup, len(issues))

	for _, issue := range issues {
		d := map[string]interface{}{
			"grant_id": issue.Grant.ID,
			"role":     issue.Grant.Role,
		}
		if issue.Grant.Resource != nil {
			d["resource"] = issue.Grant.Resource.GlobalURN
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
		if _, ok := grouped[issue.AccountID]; !ok {
			grouped[issue.AccountID] = &accountGroup{}
		}
		grouped[issue.AccountID].grants = append(grouped[issue.AccountID].grants, d)
	}

	totalDrifted := len(issues)
	totalAccounts := len(grouped)

	accountIDs := make([]string, 0, len(grouped))
	for id := range grouped {
		accountIDs = append(accountIDs, id)
	}
	sort.Strings(accountIDs)

	accounts := make([]map[string]interface{}, 0, len(grouped))
	for _, id := range accountIDs {
		accounts = append(accounts, map[string]interface{}{
			"account_id": id,
			"grants":     grouped[id].grants,
		})
	}

	dedupKey := fmt.Sprintf("drift-check:admin:%s", hashAccountIDs(accountIDs))

	severity := severityWarning
	if totalFailures > 0 {
		severity = severityCritical
	}

	recreated := totalDrifted - totalFailures - totalNotApplicable
	summary := fmt.Sprintf("Guardian: %d drifted grant(s) across %d critical bot(s) (%d recreated, %d failed, %d not_applicable)",
		totalDrifted, totalAccounts, recreated, totalFailures, totalNotApplicable)

	event := Event{
		RoutingKey:  adminTeamKey,
		DedupKey:    dedupKey,
		EventAction: eventActionTrigger,
		Summary:     summary,
		Source:      "guardian",
		Severity:    severity,
		CustomDetails: map[string]interface{}{
			"total_drifted":              totalDrifted,
			"remediation_failures":       totalFailures,
			"remediation_not_applicable": totalNotApplicable,
			"accounts":                   accounts,
		},
	}

	if err := m.pd.Send(ctx, event); err != nil {
		m.logger.Error(ctx, "failed to trigger drift check alert", "error", err)
		return []error{err}
	}

	m.logger.Info(ctx, "pagerduty drift-check alert triggered", "dedup_key", dedupKey)
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
