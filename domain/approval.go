package domain

import (
	"strings"
	"time"
)

const (
	ApprovalStatusPending  = "pending"
	ApprovalStatusBlocked  = "blocked"
	ApprovalStatusSkipped  = "skipped"
	ApprovalStatusApproved = "approved"
	ApprovalStatusRejected = "rejected"
)

type Approval struct {
	ID            string  `json:"id" yaml:"id"`
	Name          string  `json:"name" yaml:"name"`
	Index         int     `json:"-" yaml:"-"`
	AppealID      string  `json:"appeal_id" yaml:"appeal_id"`
	Status        string  `json:"status" yaml:"status"`
	Actor         *string `json:"actor" yaml:"actor"`
	Reason        string  `json:"reason,omitempty" yaml:"reason,omitempty"`
	PolicyID      string  `json:"policy_id" yaml:"policy_id"`
	PolicyVersion uint    `json:"policy_version" yaml:"policy_version"`

	Approvers []string `json:"approvers,omitempty" yaml:"approvers,omitempty"`
	Appeal    *Appeal  `json:"appeal,omitempty" yaml:"appeal,omitempty"`

	IsStale        bool `json:"is_stale,omitempty" yaml:"is_stale,omitempty"`
	AppealRevision uint `json:"appeal_revision" yaml:"appeal_revision"`

	CreatedAt time.Time `json:"created_at,omitempty" yaml:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
}

func (a *Approval) Approve() {
	a.Status = ApprovalStatusApproved
}

func (a *Approval) Reject() {
	a.Status = ApprovalStatusRejected
}

func (a *Approval) Skip() {
	a.Status = ApprovalStatusSkipped
}

func (a *Approval) IsManualApproval() bool {
	return len(a.Approvers) > 0
}

func (a *Approval) IsExistingApprover(approver string) bool {
	for _, v := range a.Approvers {
		if strings.EqualFold(approver, v) {
			return true
		}
	}

	return false
}

type ListApprovalsFilter struct {
	Q              string   `mapstructure:"q" json:"q,omitempty" validate:"omitempty"`
	AccountID      string   `mapstructure:"account_id" json:"account_id,omitempty" validate:"omitempty,required"`
	AccountTypes   []string `mapstructure:"account_types" json:"account_types,omitempty" validate:"omitempty,min=1"`
	ResourceTypes  []string `mapstructure:"resource_types" json:"resource_types,omitempty" validate:"omitempty,min=1"`
	CreatedBy      string   `mapstructure:"created_by" json:"created_by,omitempty" validate:"omitempty,required"`
	Statuses       []string `mapstructure:"statuses" json:"statuses,omitempty" validate:"omitempty,min=1"`
	OrderBy        []string `mapstructure:"order_by" json:"order_by,omitempty" validate:"omitempty,min=1"`
	Size           int      `mapstructure:"size" json:"size,omitempty" validate:"omitempty"`
	Offset         int      `mapstructure:"offset" json:"offset,omitempty" validate:"omitempty"`
	AppealStatuses []string `mapstructure:"appeal_statuses" json:"appeal_statuses,omitempty" validate:"omitempty,min=1"`
	Stale          bool     `mapstructure:"stale" json:"stale,omitempty" validate:"omitempty"`
	RoleStartsWith string   `mapstructure:"role_starts_with" json:"role_starts_with,omitempty" validate:"omitempty"`
	RoleEndsWith   string   `mapstructure:"role_ends_with" json:"role_ends_with,omitempty" validate:"omitempty"`
	RoleContains   string   `mapstructure:"role_contains" json:"role_contains,omitempty" validate:"omitempty"`
	StepNames      []string `mapstructure:"step_names" json:"step_names,omitempty" validate:"omitempty,min=1"`
	ProviderTypes  []string `mapstructure:"provider_types" json:"provider_types,omitempty" validate:"omitempty,min=1"`
	ProviderURNs   []string `mapstructure:"provider_urns" json:"provider_urns,omitempty" validate:"omitempty,min=1"`
	Actors         []string `mapstructure:"actors" json:"actors,omitempty" validate:"omitempty,min=1"`
}
