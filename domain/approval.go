package domain

import (
	"strings"
	"time"

	"github.com/goto/guardian/pkg/slices"
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

	AllowFailed           bool                   `json:"allow_failed" yaml:"allow_failed"`
	DontAllowSelfApproval bool                   `json:"dont_allow_self_approval" yaml:"dont_allow_self_approval"`
	Details               map[string]interface{} `json:"details" yaml:"details"`

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
	Q                        string    `mapstructure:"q" json:"q,omitempty" validate:"omitempty"`
	AccountID                string    `mapstructure:"account_id" json:"account_id,omitempty" validate:"omitempty,required"`
	AccountTypes             []string  `mapstructure:"account_types" json:"account_types,omitempty" validate:"omitempty,min=1"`
	ResourceTypes            []string  `mapstructure:"resource_types" json:"resource_types,omitempty" validate:"omitempty,min=1"`
	CreatedBy                string    `mapstructure:"created_by" json:"created_by,omitempty" validate:"omitempty,required"`
	Statuses                 []string  `mapstructure:"statuses" json:"statuses,omitempty" validate:"omitempty,min=1"`
	OrderBy                  []string  `mapstructure:"order_by" json:"order_by,omitempty" validate:"omitempty,min=1"`
	Size                     int       `mapstructure:"size" json:"size,omitempty" validate:"omitempty"`
	Offset                   int       `mapstructure:"offset" json:"offset,omitempty" validate:"omitempty"`
	AppealStatuses           []string  `mapstructure:"appeal_statuses" json:"appeal_statuses,omitempty" validate:"omitempty,min=1"`
	Stale                    bool      `mapstructure:"stale" json:"stale,omitempty" validate:"omitempty"`
	RoleStartsWith           string    `mapstructure:"role_starts_with" json:"role_starts_with,omitempty" validate:"omitempty"`
	RoleEndsWith             string    `mapstructure:"role_ends_with" json:"role_ends_with,omitempty" validate:"omitempty"`
	RoleContains             string    `mapstructure:"role_contains" json:"role_contains,omitempty" validate:"omitempty"`
	StepNames                []string  `mapstructure:"step_names" json:"step_names,omitempty" validate:"omitempty,min=1"`
	ProviderTypes            []string  `mapstructure:"provider_types" json:"provider_types,omitempty" validate:"omitempty,min=1"`
	ProviderURNs             []string  `mapstructure:"provider_urns" json:"provider_urns,omitempty" validate:"omitempty,min=1"`
	Actors                   []string  `mapstructure:"actors" json:"actors,omitempty" validate:"omitempty,min=1"`
	StartTime                time.Time `mapstructure:"start_time" json:"start_time,omitempty"`
	EndTime                  time.Time `mapstructure:"end_time" json:"end_time,omitempty"`
	FieldMasks               []string  `mapstructure:"field_masks" json:"field_masks,omitempty"`
	SummaryGroupBys          []string  `mapstructure:"summary_group_bys" json:"summary_group_bys,omitempty"`
	SummaryUniques           []string  `mapstructure:"summary_uniques" json:"summary_uniques,omitempty"`
	ResourceUrns             []string  `mapstructure:"resource_urns" json:"resource_urns,omitempty"`
	Roles                    []string  `mapstructure:"roles" json:"roles,omitempty"`
	Requestors               []string  `mapstructure:"requestors" json:"requestors,omitempty"`
	AccountIDs               []string  `mapstructure:"account_ids" json:"account_ids,omitempty"`
	ProviderUrnStartsWith    string    `mapstructure:"provider_urn_starts_with" json:"provider_urn_starts_with,omitempty" validate:"omitempty"`
	ProviderUrnEndsWith      string    `mapstructure:"provider_urn_ends_with" json:"provider_urn_ends_with,omitempty" validate:"omitempty"`
	ProviderUrnContains      string    `mapstructure:"provider_urn_contains" json:"provider_urn_contains,omitempty" validate:"omitempty"`
	ProviderUrnNotStartsWith string    `mapstructure:"provider_urn_not_starts_with" json:"provider_urn_not_starts_with,omitempty" validate:"omitempty"`
	ProviderUrnNotEndsWith   string    `mapstructure:"provider_urn_not_ends_with" json:"provider_urn_not_ends_with,omitempty" validate:"omitempty"`
	ProviderUrnNotContains   string    `mapstructure:"provider_urn_not_contains" json:"provider_urn_not_contains,omitempty" validate:"omitempty"`
	AppealDurations          []string  `mapstructure:"appeal_durations" json:"appeal_durations,omitempty" validate:"omitempty"`
	NotAppealDurations       []string  `mapstructure:"not_appeal_durations" json:"not_appeal_durations,omitempty" validate:"omitempty"`
	AppealDetailsPaths       []string  `mapstructure:"appeal_details_paths" json:"appeal_details_paths,omitempty" validate:"omitempty"`
	AppealDetails            []string  `mapstructure:"appeal_details" json:"appeal_details,omitempty" validate:"omitempty"`
	NotAppealDetails         []string  `mapstructure:"not_appeal_details" json:"not_appeal_details,omitempty" validate:"omitempty"`
	RoleNotStartsWith        string    `mapstructure:"role_not_starts_with" json:"role_not_starts_with,omitempty" validate:"omitempty"`
	RoleNotEndsWith          string    `mapstructure:"role_not_ends_with" json:"role_not_ends_with,omitempty" validate:"omitempty"`
	RoleNotContains          string    `mapstructure:"role_not_contains" json:"role_not_contains,omitempty" validate:"omitempty"`

	AppealDetailsStartsWith      string   `mapstructure:"appeal_details_starts_with" json:"appeal_details_starts_with,omitempty" validate:"omitempty"`
	AppealDetailsEndsWith        string   `mapstructure:"appeal_details_ends_with" json:"appeal_details_ends_with,omitempty" validate:"omitempty"`
	AppealDetailsContains        string   `mapstructure:"appeal_details_contains" json:"appeal_details_contains,omitempty" validate:"omitempty"`
	AppealDetailsNotStartsWith   string   `mapstructure:"appeal_details_not_starts_with" json:"appeal_details_not_starts_with,omitempty" validate:"omitempty"`
	AppealDetailsNotEndsWith     string   `mapstructure:"appeal_details_not_ends_with" json:"appeal_details_not_ends_with,omitempty" validate:"omitempty"`
	AppealDetailsNotContains     string   `mapstructure:"appeal_details_not_contains" json:"appeal_details_not_contains,omitempty" validate:"omitempty"`
	GroupIDs                     []string `mapstructure:"group_ids" json:"group_ids,omitempty" validate:"omitempty"`
	GroupTypes                   []string `mapstructure:"group_types" json:"group_types,omitempty" validate:"omitempty"`
	GroupTypeStartsWith          string   `mapstructure:"group_type_starts_with" json:"group_type_starts_with,omitempty" validate:"omitempty"`
	GroupTypeEndsWith            string   `mapstructure:"group_type_ends_with" json:"group_type_ends_with,omitempty" validate:"omitempty"`
	GroupTypeContains            string   `mapstructure:"group_type_contains" json:"group_type_contains,omitempty" validate:"omitempty"`
	GroupTypeNotStartsWith       string   `mapstructure:"group_type_not_starts_with" json:"group_type_not_starts_with,omitempty" validate:"omitempty"`
	GroupTypeNotEndsWith         string   `mapstructure:"group_type_not_ends_with" json:"group_type_not_ends_with,omitempty" validate:"omitempty"`
	GroupTypeNotContains         string   `mapstructure:"group_type_not_contains" json:"group_type_not_contains,omitempty" validate:"omitempty"`
	AppealForSelf                bool     `mapstructure:"appeal_for_self" json:"appeal_for_self,omitempty"`
	AppealDetailsForSelfCriteria []string `mapstructure:"appeal_details_for_self_criteria" json:"appeal_details_for_self_criteria,omitempty" validate:"omitempty"`
}

func (af ListApprovalsFilter) WithSummary() bool {
	return len(af.SummaryGroupBys) > 0 || len(af.SummaryUniques) > 0
}

func (af ListApprovalsFilter) WithApprovals() bool {
	return !slices.GenericsSliceContainsOne(af.FieldMasks, "approvals")
}

func (af ListApprovalsFilter) WithTotal() bool {
	return !slices.GenericsSliceContainsOne(af.FieldMasks, "total")
}
