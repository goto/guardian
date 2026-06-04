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

const (
	GrantDriftCheckEvent = "grant_drift_check"
)

// NotificationSender is the interface for delivering events to a notifier.
type NotificationSender interface {
	Send(ctx context.Context, event Event) error
}
type AlertManagerConfig struct {
	Provider    string `mapstructure:"provider" default:"siren"`
	Endpoint    string `mapstructure:"endpoint"`
	Environment string `mapstructure:"environment" default:"development"`
}

func GetAlertManagerSender(cfg AlertManagerConfig) NotificationSender {
	switch cfg.Provider {
	case "siren":
		if cfg.Endpoint != "" {
			return NewSirenClient(cfg.Endpoint, cfg.Environment)
		}
	case "pagerduty":
		return NewPDClient()
	}
	return &NoOpSender{}
}

type NoOpSender struct{}

func (s *NoOpSender) Send(_ context.Context, _ Event) error {
	return nil
}

type Event struct {
	Title    string
	Summary  string
	Data     map[string]interface{}
	DedupKey string
	Team     string
	Severity string
	Labels   map[string]string
}

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
	notificationSender NotificationSender
	logger             log.Logger
}

func New(notificationSender NotificationSender, logger log.Logger) *AlertManager {
	return &AlertManager{
		notificationSender: notificationSender,
		logger:             logger,
	}
}

// NotifyDriftCheck sends a single summary alert to adminTeam listing all drifted
// dedup_key: drift-check:admin:{hash(sorted accountIDs)}
func (m *AlertManager) NotifyDriftCheck(ctx context.Context, req NotifyDriftCheckRequest) error {
	totalFailures := 0

	grouped := make(map[string]*accountGroup, len(req.Issues))

	for _, issue := range req.Issues {
		d := map[string]interface{}{
			"role": issue.Grant.Role,
		}
		if issue.Grant.Resource != nil {
			d["resource"] = issue.Grant.Resource.URN
		}
		if issue.RemediationError != "" {
			d["remediation_status"] = "failed"
			d["remediation_error"] = issue.RemediationError
			totalFailures++
		} else {
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

	recreated := totalDrifted - totalFailures
	summary := fmt.Sprintf("Guardian: %d drifted grant(s) across %d critical bot(s) (%d recreated, %d failed)",
		totalDrifted, totalAccounts, recreated, totalFailures)

	event := Event{
		Title:    GrantDriftCheckEvent,
		Summary:  summary,
		DedupKey: dedupKey,
		Data: map[string]interface{}{
			"total_drifted":        totalDrifted,
			"remediation_failures": totalFailures,
			"accounts":             accounts,
		},
		Team:     req.AdminTeam,
		Severity: severity,
	}

	if req.DryRun {
		eventJSON, _ := json.Marshal(event)
		m.logger.Info(ctx, "dry run enabled: skipping sending drift check alert", "event", string(eventJSON))
		return nil
	}

	if err := m.notificationSender.Send(ctx, event); err != nil {
		m.logger.Error(ctx, "failed to trigger drift check alert", "error", err)
		return err
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
