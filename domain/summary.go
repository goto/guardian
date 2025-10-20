package domain

import (
	"errors"
)

var (
	ErrInvalidUniqueInput          = errors.New(`invalid unique input. valid format: "table_name.column_name"`)
	ErrEmptyUniqueTableName        = errors.New("empty unique table name")
	ErrEmptyUniqueColumnName       = errors.New("empty unique column name")
	ErrNotSupportedUniqueTableName = errors.New("not supported unique table name")

	ErrInvalidGroupInput          = errors.New(`invalid group input. valid format: "table_name.column_name"`)
	ErrEmptyGroupTableName        = errors.New("empty group table name")
	ErrEmptyGroupColumnName       = errors.New("empty group column name")
	ErrNotSupportedGroupTableName = errors.New("not supported group table name")
)

type SummaryParameters struct {
	GroupBys []string       `mapstructure:"group_bys" validate:"required,min=1,dive,oneof=status step_name actor email"`
	Filters  map[string]any `mapstructure:"filters" validate:"omitempty"`
}

type SummaryResult struct {
	AppliedParameters *SummaryParameters `json:"applied_parameters,omitempty"`
	SummaryGroups     []*SummaryGroup    `json:"summary_groups,omitempty"`
	SummaryUniques    []*SummaryUnique   `json:"summary_uniques,omitempty"`
	Count             int32              `json:"count,omitempty"`
	GroupsCount       int32              `json:"groups_count,omitempty"`
	UniquesCount      int32              `json:"uniques_count,omitempty"`
}

type SummaryUnique struct {
	Field  string        `json:"field,omitempty"`
	Values []interface{} `json:"values,omitempty"`
	Count  int32         `json:"count,omitempty"`
}

type SummaryGroup struct {
	GroupFields map[string]any `json:"group_fields,omitempty"`
	Count       int32          `json:"count,omitempty"`
}
