package guardian

import (
	"fmt"
	"slices"

	"github.com/goto/guardian/domain"
)

const (
	packagePermissionMember = "member"
	packagePermissionAdmin  = "admin"

	resourceTypePackage = "package"
)

var (
	validPermissions = []string{packagePermissionMember, packagePermissionAdmin}
)

type config struct {
	*domain.ProviderConfig
}

func (c *config) validate() error {
	resourceTypes := c.GetResourceTypes()
	if len(resourceTypes) != 1 && resourceTypes[0] != resourceTypePackage {
		return fmt.Errorf("only resource type %q is supported", resourceTypePackage)
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
