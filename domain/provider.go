package domain

import (
	"fmt"
	"sort"
	"time"
)

const (
	ProviderTypeAliCloudRAM = "alicloud_ram"
	ProviderTypeBigQuery    = "bigquery"
	ProviderTypeMetabase    = "metabase"
	ProviderTypeGrafana     = "grafana"
	ProviderTypeTableau     = "tableau"
	ProviderTypeGCloudIAM   = "gcloud_iam"
	ProviderTypeNoOp        = "noop"
	ProviderTypeGCS         = "gcs"
	ProviderTypePolicyTag   = "dataplex"
	ProviderTypeShield      = "shield"
	ProviderTypeGitlab      = "gitlab"
	ProviderTypeGate        = "gate"
	ProviderTypeMaxCompute  = "maxcompute"
	ProviderTypeOss         = "oss"
	ProviderTypeGoogleGroup = "google_group"
)

// Role is the configuration to define a role and mapping the permissions in the provider
type Role struct {
	ID          string        `json:"id" yaml:"id" validate:"required"`
	Name        string        `json:"name" yaml:"name" validate:"required"`
	Description string        `json:"description,omitempty" yaml:"description"`
	Permissions []interface{} `json:"permissions" yaml:"permissions" validate:"required"`
}

// GetOrderedPermissions returns the permissions as a string slice
func (r Role) GetOrderedPermissions() []string {
	permissions := []string{}
	for _, p := range r.Permissions {
		permissions = append(permissions, fmt.Sprintf("%s", p))
	}
	sort.Strings(permissions)
	return permissions
}

// PolicyConfig is the configuration that defines which policy is being used in the provider
type PolicyConfig struct {
	ID      string `json:"id" yaml:"id" validate:"required"`
	Version int    `json:"version" yaml:"version" validate:"required"`
}

// ResourceConfig is the configuration for a resource type within a provider
type ResourceConfig struct {
	Type   string        `json:"type" yaml:"type" validate:"required"`
	Filter string        `json:"filter" yaml:"filter"`
	Policy *PolicyConfig `json:"policy" yaml:"policy"`
	Roles  []*Role       `json:"roles" yaml:"roles" validate:"required"`
}

// AppealConfig is the policy configuration of the appeal
type AppealConfig struct {
	AllowPermanentAccess         bool   `json:"allow_permanent_access" yaml:"allow_permanent_access"`
	AllowActiveAccessExtensionIn string `json:"allow_active_access_extension_in" yaml:"allow_active_access_extension_in" validate:"required"`
}

type ProviderConfig struct {
	Type                string               `json:"type" yaml:"type" validate:"required,oneof=alicloud_ram google_bigquery metabase grafana tableau gcloud_iam noop gcs shield"`
	URN                 string               `json:"urn" yaml:"urn" validate:"required"`
	AllowedAccountTypes []string             `json:"allowed_account_types" yaml:"allowed_account_types" validate:"omitempty,min=1"`
	Labels              map[string]string    `json:"labels,omitempty" yaml:"labels,omitempty"`
	Credentials         interface{}          `json:"credentials,omitempty" yaml:"credentials" validate:"required"`
	Appeal              *AppealConfig        `json:"appeal,omitempty" yaml:"appeal,omitempty" validate:"required"`
	Resources           []*ResourceConfig    `json:"resources" yaml:"resources" validate:"required"`
	Parameters          []*ProviderParameter `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	Activity            *ActivityConfig      `json:"activity,omitempty" yaml:"activity,omitempty"`
	Policies            []*ProviderPolicy    `json:"policies,omitempty" yaml:"policies,omitempty"`
}

type ProviderParameter struct {
	Key         string `json:"key" yaml:"key" validate:"required"`
	Label       string `json:"label" yaml:"label" validate:"required"`
	Required    bool   `json:"required" yaml:"required" validate:"required"`
	Description string `json:"description" yaml:"description"`
}

func (pc ProviderConfig) GetResourceTypes() (resourceTypes []string) {
	for _, rc := range pc.Resources {
		resourceTypes = append(resourceTypes, rc.Type)
	}
	return
}

func (pc ProviderConfig) GetParameterKeys() (keys []string) {
	for _, param := range pc.Parameters {
		keys = append(keys, param.Key)
	}
	return
}

func (pc ProviderConfig) GetFilterForResourceType(resourceType string) string {
	for _, resource := range pc.Resources {
		if resource.Type == resourceType {
			return resource.Filter
		}
	}
	return ""
}

type Provider struct {
	ID        string          `json:"id" yaml:"id"`
	Type      string          `json:"type" yaml:"type"`
	URN       string          `json:"urn" yaml:"urn"`
	Config    *ProviderConfig `json:"config" yaml:"config"`
	CreatedAt time.Time       `json:"created_at,omitempty" yaml:"created_at,omitempty"`
	UpdatedAt time.Time       `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
}

type ProviderType struct {
	Name          string   `json:"name" yaml:"name"`
	ResourceTypes []string `json:"resource_types" yaml:"resource_types"`
}

type ActivityConfig struct {
	Source  string
	Options map[string]interface{}
}

type ProviderPolicy struct {
	When   string `json:"when" yaml:"when"`
	Policy string `json:"policy" yaml:"policy"`
}
