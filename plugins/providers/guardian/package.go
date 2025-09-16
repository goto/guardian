package guardian

import (
	"errors"
	"fmt"
)

type PackageInfo struct {
	Owner       string            `json:"owner" mapstructure:"owner"`
	Description string            `json:"description" mapstructure:"description"`
	Accounts    []*PackageAccount `json:"accounts" mapstructure:"accounts"`
}

func (p *PackageInfo) Validate() error {
	if p == nil {
		return errors.New("package details is required")
	}
	if p.Owner == "" {
		return errors.New("owner is required")
	}

	for i, a := range p.Accounts {
		if a.ProviderType == "" {
			return fmt.Errorf("provider_type is required for package account at index %d", i)
		}
		if a.Type == "" {
			return fmt.Errorf("type is required for package account at index %d", i)
		}
		if a.ID == "" {
			return fmt.Errorf("id is required for package account at index %d", i)
		}
		if a.GrantParameters != nil {
			if a.GrantParameters.Role == "" {
				return fmt.Errorf("role is required in grant parameters for package account at index %d", i)
			}
		}
	}

	return nil
}

type PackageGrantParameters struct {
	// Role value specified here will be assigned to the dependency grant(s) with the matching provider type and resource type
	Role string `json:"role" mapstructure:"role"`
}

type PackageAccount struct {
	ProviderType string `json:"provider_type" mapstructure:"provider_type"`

	// Type is the account_type of the account associated with the package
	Type string `json:"type" mapstructure:"type"`

	// ID is the unique identifier of the account associated with the package
	ID string `json:"id" mapstructure:"id"`

	// GroupName string `json:"group_name,omitempty" mapstructure:"group_name,omitempty"`

	// GrantParameters configures values that will be applied to the dependency grants when user's request to become package member is approved
	GrantParameters *PackageGrantParameters `json:"grant" mapstructure:"grant"`
}
