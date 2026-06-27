package domain

import "time"

type IAMProviderType string

const (
	IAMProviderTypeShield IAMProviderType = "shield"
	IAMProviderTypeHTTP   IAMProviderType = "http"
)

type IAMConfig struct {
	Provider IAMProviderType   `json:"provider" yaml:"provider" validate:"required,oneof=http shield"`
	Config   interface{}       `json:"config" yaml:"config" validate:"required"`
	Schema   map[string]string `json:"schema" yaml:"schema"`
}

type Group struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Slug     string                 `json:"slug"`
	OrgID    string                 `json:"orgId"`
	Metadata map[string]interface{} `json:"metadata"`
}

type User struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Slug      string                 `json:"slug"`
	Email     string                 `json:"email"`
	Metadata  map[string]interface{} `json:"metadata"`
	CreatedAt time.Time              `json:"createdAt"`
	UpdatedAt time.Time              `json:"updatedAt"`
}

type IAMManager interface {
	ParseConfig(*IAMConfig) (SensitiveConfig, error)
	GetClient(SensitiveConfig) (IAMClient, error)
}

// IAMClient interface
type IAMClient interface {
	GetUser(id string) (interface{}, error)
	GetUserGroups(id string) (interface{}, error)
}
