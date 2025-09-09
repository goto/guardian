package domain

type Summary struct {
	SummaryGroups []*SummaryGroup `json:"summary_groups,omitempty"`
	Total         int32           `json:"total"`
}

type SummaryGroup struct {
	Groups map[string]string `json:"groups,omitempty"`
	Total  int32             `json:"total"`
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
}

type ApprovalsSummaryFilter struct {
	Statuses  []string `mapstructure:"statuses" validate:"omitempty,min=1"`
	StepNames []string `mapstructure:"step_names" validate:"omitempty,min=1"`
}

type ApproversSummaryFilter struct {
	Emails []string `mapstructure:"emails" validate:"omitempty,min=1"`
}
