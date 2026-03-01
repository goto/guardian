package guardian

import (
	"fmt"
	"slices"
	"strings"

	"github.com/goto/guardian/domain"
	"github.com/mitchellh/mapstructure"
)

const (
	providerType = "guardian"

	resourceTypePackage = "package"

	packagePermissionMember = "member"
	packagePermissionAdmin  = "admin"

	providerParameterKeyAccounts = "accounts"

	accountTypeUser = "user"
	accountTypeBot  = "bot"
)

var (
	validPermissions  = []string{packagePermissionMember, packagePermissionAdmin}
	validAccountTypes = []string{accountTypeUser, accountTypeBot}
)

type config struct {
	*domain.ProviderConfig
}

func (c *config) validate() error {
	resourceTypes := c.GetResourceTypes()
	if len(resourceTypes) == 0 {
		return fmt.Errorf("at least one resource type is required")
	}

	for _, rc := range c.Resources {
		switch {
		case strings.HasPrefix(rc.Type, resourceTypePackage):
			if err := c.validatePackageResource(rc); err != nil {
				return err
			}
		case strings.HasPrefix(rc.Type, resourceTypeAction):
			if err := c.validateActionResource(rc); err != nil {
				return err
			}
		case strings.HasPrefix(rc.Type, resourceTypeOptimus):
			if err := c.validateOptimusResource(rc); err != nil {
				return err
			}
		default:
			return fmt.Errorf("resource type must have prefix %q, %q, or %q", resourceTypePackage, resourceTypeAction, resourceTypeOptimus)
		}
	}

	return nil
}

func (c *config) validatePackageResource(rc *domain.ResourceConfig) error {
	for _, roleConfig := range rc.Roles {
		if len(roleConfig.Permissions) == 0 {
			return fmt.Errorf("permissions are missing for role: %q", roleConfig.ID)
		}
		for _, permission := range roleConfig.Permissions {
			permissionStr, ok := permission.(string)
			if !ok {
				return fmt.Errorf("unexpected permission type: %T, expected: string", permission)
			}
			if !slices.Contains(validPermissions, permissionStr) {
				return fmt.Errorf("invalid permission %q", permission)
			}
		}
	}

	hasAccountsParam := false
	for _, p := range c.Parameters {
		if p.Key == providerParameterKeyAccounts {
			hasAccountsParam = true
			break
		}
	}
	if !hasAccountsParam {
		return fmt.Errorf("provider parameter %q is required for package resource type", providerParameterKeyAccounts)
	}

	return nil
}

func (c *config) validateActionResource(rc *domain.ResourceConfig) error {
	return c.validateResourceDetails(rc)
}

func (c *config) validateOptimusResource(rc *domain.ResourceConfig) error {
	return c.validateResourceDetails(rc)
}

func (c *config) validateResourceDetails(rc *domain.ResourceConfig) error {
	if rc.Details == nil {
		return nil
	}

	var actionMetadata ActionMetadata
	if err := mapstructure.Decode(rc.Details, &actionMetadata); err != nil {
		return fmt.Errorf("failed to decode resource config details: %w", err)
	}
	if err := actionMetadata.Validate(); err != nil {
		return fmt.Errorf("invalid resource config details: %w", err)
	}
	return nil
}
