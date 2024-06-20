package report

import (
	"time"
)

type PendingApprovalModel struct {
	AppealID        string    `json:"id" yaml:"id"`
	Approver        string    `json:"approver" yaml:"approver"`
	AppealCreatedAt time.Time `json:"created_at" yaml:"created_at"`
}

type PendingApproval struct {
	Approver string
	Count    int
	Appeals  []PendingAppeal // ideally []*domain.Appeal, but only ID is needed for now
}

type PendingAppeal struct {
	ID string
}

type PendingApprovalsReportFilter struct {
	AppealStatuses   []string `mapstructure:"appeal_statuses" validate:"omitempty,min=1"`
	ApprovalStatuses []string `mapstructure:"approval_statuses" validate:"omitempty,min=1"`
	ApprovalStale    *bool    `mapstructure:"approval_stale"`
}
