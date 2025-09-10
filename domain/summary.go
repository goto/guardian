package domain

type SummaryParameters struct { // dipake di request & response
	GroupBys []string       `mapstructure:"group_bys" validate:"required,min=1,dive,oneof=status step_name actor email"`
	Filters  map[string]any `mapstructure:"filters" validate:"omitempty"`
}

type SummaryResult struct {
	AppliedParameters *SummaryParameters `json:"applied_parameters,omitempty"`
	SummaryGroups     []*SummaryGroup    `json:"summary_groups,omitempty"`
	Total             int32              `json:"total"`
}

type SummaryGroup struct {
	GroupFields map[string]any `json:"group_fields,omitempty"`
	Total       int32          `json:"total"`
}

type SummaryFilter struct {
	AppealsFilter   *AppealsSummaryFilter   `mapstructure:"appeals_filter" validate:"omitempty,dive"`
	ApprovalsFilter *ApprovalsSummaryFilter `mapstructure:"approvals_filter" validate:"omitempty,dive"`
	ApproversFilter *ApproversSummaryFilter `mapstructure:"approvers_filter" validate:"omitempty,dive"`
}

type AppealsSummaryFilter struct {
	Statuses       []string `mapstructure:"statuses" validate:"omitempty,min=1"`
	RoleStartsWith []string `mapstructure:"role_starts_with" validate:"omitempty,min=1"`
	RoleEndsWith   []string `mapstructure:"role_ends_with" validate:"omitempty,min=1"`
	RoleContains   []string `mapstructure:"role_contains" validate:"omitempty,min=1"`
	AccountTypes   []string `mapstructure:"account_types" validate:"omitempty,min=1"`
}

type ApprovalsSummaryFilter struct {
	Statuses  []string `mapstructure:"statuses" validate:"omitempty,min=1"`
	StepNames []string `mapstructure:"step_names" validate:"omitempty,min=1"`
	Stale     bool     `mapstructure:"stale"`
}

type ApproversSummaryFilter struct {
	Emails []string `mapstructure:"emails" validate:"omitempty,min=1"`
}
