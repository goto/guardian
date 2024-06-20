package report

import (
	"time"
)

type PendingApprovalsReport struct {
	AppealID        string    `json:"id" yaml:"id"`
	Approver        string    `json:"approver" yaml:"approver"`
	AppealCreatedAt time.Time `json:"created_at" yaml:"created_at"`
}

type PendingApprovalsReportFilter struct {
	AppealStatuses   []string `mapstructure:"appeal_statuses" validate:"omitempty,min=1"`
	ApprovalStatuses []string `mapstructure:"approval_statuses" validate:"omitempty,min=1"`
	ApprovalStale    *bool    `mapstructure:"approval_stale"`
}
