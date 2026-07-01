package jobs

import (
	"strings"

	"github.com/mitchellh/mapstructure"
)

type Type string

const (
	TypeFetchResources             Type = "fetch_resources"
	TypeExpiringGrantNotification  Type = "expiring_grant_notification"
	TypeRevokeExpiredGrants        Type = "revoke_expired_grants"
	TypeRevokeGrantsByUserCriteria Type = "revoke_grants_by_user_criteria"
	TypeGrantDormancyCheck         Type = "grant_dormancy_check"
	TypePendingApprovalsReminder   Type = "pending_approvals_reminder"
	TypeGrantDriftCheck            Type = "grant_drift_check"
	TypeBotExpirationAlert         Type = "bot_expiration_alert"
)

type Job struct {
	Type   Type
	Config Config `mapstructure:"config"`
}

// Config is a map of job-specific configuration
type Config map[string]interface{}

func (c Config) Decode(v interface{}) error {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result: v,
		// Config keys are typically snake_case (e.g. "account_ids") while struct
		// fields are CamelCase (e.g. AccountIDs) with no mapstructure tag, so the
		// default EqualFold matcher never binds them. Ignore underscores so any
		// snake_case config key binds to its corresponding struct field.
		MatchName: func(mapKey, fieldName string) bool {
			return strings.EqualFold(strings.ReplaceAll(mapKey, "_", ""), fieldName)
		},
	})
	if err != nil {
		return err
	}
	return decoder.Decode(c)
}
