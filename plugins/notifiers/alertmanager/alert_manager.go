package alertmanager

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
)

type accountGroup struct {
	grants []map[string]interface{}
}

type NotifyDriftCheckRequest struct {
	DryRun            bool
	AdminTeam         string
	Issues            []domain.GrantDriftIssue
	OnSuccessSeverity string
	OnFailureSeverity string
}

type AlertManager struct {
	pd     PDSender
	logger log.Logger
}

// TODO: implementation of alert manager should utilize shield team instead of direct PD integration
func New(pdClient PDSender, logger log.Logger) *AlertManager {
	return &AlertManager{
		pd:     pdClient,
		logger: logger,
	}
}

// NotifyDriftCheck sends a single summary alert to adminTeam listing all drifted
// dedup_key: drift-check:admin:{hash(sorted accountIDs)}
func (m *AlertManager) NotifyDriftCheck(ctx context.Context, req NotifyDriftCheckRequest) []error {
	totalFailures := 0
	totalNotApplicable := 0

	grouped := make(map[string]*accountGroup, len(req.Issues))

	for _, issue := range req.Issues {
		d := map[string]interface{}{
			"role": issue.Grant.Role,
		}
		if issue.Grant.Resource != nil {
			d["resource"] = issue.Grant.Resource.URN
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

	totalDrifted := len(req.Issues)
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

	severity := req.OnSuccessSeverity
	if totalFailures > 0 {
		severity = req.OnFailureSeverity
	}

	recreated := totalDrifted - totalFailures - totalNotApplicable
	summary := fmt.Sprintf("Guardian: %d drifted grant(s) across %d critical bot(s) (%d recreated, %d failed, %d not_applicable)",
		totalDrifted, totalAccounts, recreated, totalFailures, totalNotApplicable)

	event := Event{
		RoutingKey:  req.AdminTeam,
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

	if req.DryRun {
		eventJSON, _ := json.Marshal(event)
		m.logger.Info(ctx, "dry run enabled: skipping sending drift check alert", "event", string(eventJSON))
		return nil
	}

	if err := m.pd.Send(ctx, event); err != nil {
		m.logger.Error(ctx, "failed to trigger drift check alert", "error", err)
		return []error{err}
	}

	m.logger.Info(ctx, "notify drift-check alert triggered", "dedup_key", dedupKey)
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
