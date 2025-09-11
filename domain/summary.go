package domain

type SummaryParameters struct { // dipake di request & response
	GroupBys []string       `mapstructure:"group_bys" validate:"required,min=1,dive,oneof=status step_name actor email"`
	Filters  map[string]any `mapstructure:"filters" validate:"omitempty"`
}

type SummaryResult struct {
	AppliedParameters *SummaryParameters `json:"applied_parameters,omitempty"`
	SummaryGroups     []*SummaryGroup    `json:"summary_groups,omitempty"`
	Count             int32              `json:"count"`
}

type SummaryGroup struct {
	GroupFields map[string]any `json:"group_fields,omitempty"`
	Count       int32          `json:"count"`
}
