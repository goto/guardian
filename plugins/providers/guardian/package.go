package guardian

import (
	"errors"
	"fmt"
)

type PackageInfo struct {
	CreatedBy   string                  `json:"created_by" mapstructure:"created_by"`
	Description string                  `json:"description" mapstructure:"description"`
	Accounts    []*PackageAccountConfig `json:"accounts" mapstructure:"accounts"`
}

func (p *PackageInfo) Validate() error {
	if p == nil {
		return errors.New("package details is required")
	}
	if p.CreatedBy == "" {
		return errors.New("created_by is required")
	}

	for i, a := range p.Accounts {
		if a.ProviderType == "" {
			return fmt.Errorf("provider_type is required for package account at index %d", i)
		}
		if a.AccountType == "" {
			return fmt.Errorf("account_type is required for package account at index %d", i)
		}
		if a.GrantParameters != nil {
			if a.GrantParameters.Role == "" {
				return fmt.Errorf("role is required in grant parameters for package account at index %d", i)
			}
		}
	}

	return nil
}

type GrantParameters struct {
	// Role value specified here will be assigned to the dependency grant(s) with the matching provider type and resource type
	Role string `json:"role" mapstructure:"role"`
}

type PackageAccountConfig struct {
	ProviderType string `json:"provider_type" mapstructure:"provider_type"`
	AccountType  string `json:"account_type" mapstructure:"account_type"`

	// GrantParameters configures values that will be applied to the dependency grants when user's request to become package member is approved
	GrantParameters *GrantParameters `json:"grant_parameters" mapstructure:"grant_parameters"`
}

type RequestorAccount struct {
	ProviderType string `json:"provider_type" mapstructure:"provider_type"`
	AccountType  string `json:"account_type" mapstructure:"account_type"`

	AccountID string `json:"account_id" mapstructure:"account_id"`
}
