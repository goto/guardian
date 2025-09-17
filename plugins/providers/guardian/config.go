package guardian

import (
	"fmt"
	"slices"

	"github.com/goto/guardian/domain"
)

const (
	providerType = "guardian"

	resourceTypePackage = "package"

	packagePermissionMember = "member"
	packagePermissionAdmin  = "admin"
)

var (
	validPermissions = []string{packagePermissionMember, packagePermissionAdmin}
)

type config struct {
	*domain.ProviderConfig
}

func (c *config) validate() error {
	resourceTypes := c.GetResourceTypes()
	if len(resourceTypes) != 1 {
		return fmt.Errorf("exactly one resource type must be specified")
	}
	if resourceTypes[0] != resourceTypePackage {
		return fmt.Errorf("only resource type %q is supported for provider type %q", resourceTypePackage, providerType)
	}

	rc := c.Resources[0]
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

	return nil
}
