package domain

import "time"

type Comment struct {
	ID        string    `json:"id" yaml:"id"`
	AppealID  string    `json:"appeal_id" yaml:"appeal_id"`
	CreatedBy string    `json:"created_by" yaml:"created_by"`
	Body      string    `json:"body" yaml:"body"`
	CreatedAt time.Time `json:"created_at,omitempty" yaml:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
}

type ListCommentsFilter struct {
	AppealID string
	OrderBy  []string
}
