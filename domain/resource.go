package domain

import (
	"errors"
	"time"
)

// Resource struct
type Resource struct {
	ID           string                 `json:"id" yaml:"id"`
	ProviderType string                 `json:"provider_type" yaml:"provider_type"`
	ProviderURN  string                 `json:"provider_urn" yaml:"provider_urn"`
	Type         string                 `json:"type" yaml:"type"`
	URN          string                 `json:"urn" yaml:"urn"`
	Name         string                 `json:"name" yaml:"name"`
	Details      map[string]interface{} `json:"details" yaml:"details"`
	Labels       map[string]string      `json:"labels,omitempty" yaml:"labels,omitempty"`
	CreatedAt    time.Time              `json:"created_at,omitempty" yaml:"created_at,omitempty"`
	UpdatedAt    time.Time              `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
	IsDeleted    bool                   `json:"is_deleted,omitempty" yaml:"is_deleted,omitempty"`
	ParentID     *string                `json:"parent_id,omitempty" yaml:"parent_id,omitempty"`
	Children     []*Resource            `json:"children,omitempty" yaml:"children,omitempty"`
	GlobalURN    string                 `json:"global_urn" yaml:"global_urn"`
	GroupID      string                 `json:"group_id,omitempty" yaml:"group_id,omitempty"`
	GroupType    string                 `json:"group_type,omitempty" yaml:"group_type,omitempty"`
}

func (r *Resource) Validate() error {
	if r.ProviderType == "" {
		return errors.New("provider_type is required")
	}
	if r.ProviderURN == "" {
		return errors.New("provider_urn is required")
	}
	if r.Type == "" {
		return errors.New("type is required")
	}
	if r.URN == "" {
		return errors.New("urn is required")
	}
	if r.Name == "" {
		return errors.New("name is required")
	}
	return nil
}

type ListResourcesFilter struct {
	IDs           []string          `mapstructure:"ids" validate:"omitempty,min=1"`
	IsDeleted     bool              `mapstructure:"is_deleted" validate:"omitempty"`
	ProviderType  string            `mapstructure:"provider_type" validate:"omitempty"`
	ProviderURN   string            `mapstructure:"provider_urn" validate:"omitempty"`
	Name          string            `mapstructure:"name" validate:"omitempty"`
	ResourceURN   string            `mapstructure:"urn" validate:"omitempty"`
	ResourceType  string            `mapstructure:"type" validate:"omitempty"`
	ResourceURNs  []string          `mapstructure:"urns" validate:"omitempty"`
	ResourceTypes []string          `mapstructure:"types" validate:"omitempty"`
	Details       map[string]string `mapstructure:"details"`
	Size          uint32            `mapstructure:"size" validate:"omitempty"`
	Offset        uint32            `mapstructure:"offset" validate:"omitempty"`
	OrderBy       []string          `mapstructure:"order_by" validate:"omitempty"`
	Q             string            `mapstructure:"q" validate:"omitempty"`
	GroupIDs      []string          `mapstructure:"group_ids" validate:"omitempty"`
	GroupTypes    []string          `mapstructure:"group_types" validate:"omitempty"`
}

type Resources []*Resource

func (r Resources) ToMap() map[string]*Resource {
	resources := make(map[string]*Resource, len(r))
	for _, resource := range r {
		resources[resource.ID] = resource
	}
	return resources
}
