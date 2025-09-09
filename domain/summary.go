package domain

type Summary struct {
	SummaryGroups []*SummaryGroup `json:"summary_groups,omitempty"`
	Total         int64           `json:"total"`
}

type SummaryGroup struct {
	Groups map[string]string `json:"groups,omitempty"`
	Total  int64             `json:"total"`
}

type SummaryFilter struct {
	AppealFilter   *AppealSummaryFilter   `mapstructure:"appeal_filter" validate:"omitempty,dive"`
	ApprovalFilter *ApprovalSummaryFilter `mapstructure:"approval_filter" validate:"omitempty,dive"`
	ApproverFilter *ApproverSummaryFilter `mapstructure:"approver_filter" validate:"omitempty,dive"`
}

type AppealSummaryFilter struct {
	Statuses       []string `mapstructure:"statuses" validate:"omitempty,min=1"`
	RoleStartsWith []string `mapstructure:"role_starts_with" validate:"omitempty,min=1"`
	RoleEndsWith   []string `mapstructure:"role_ends_with" validate:"omitempty,min=1"`
	RoleContains   []string `mapstructure:"role_contains" validate:"omitempty,min=1"`
}

type ApprovalSummaryFilter struct {
	Statuses  []string `mapstructure:"statuses" validate:"omitempty,min=1"`
	StepNames []string `mapstructure:"step_names" validate:"omitempty,min=1"`
}

type ApproverSummaryFilter struct {
	Emails []string `mapstructure:"emails" validate:"omitempty,min=1"`
}
