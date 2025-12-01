package guardian

import (
	"fmt"
	"slices"
	"strings"

	"github.com/goto/guardian/domain"
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
	if len(resourceTypes) != 1 || !strings.HasPrefix(resourceTypes[0], resourceTypePackage) {
		return fmt.Errorf("resource type prefix %q is required", resourceTypePackage)
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

	if len(c.Parameters) != 1 || c.Parameters[0].Key != providerParameterKeyAccounts {
		return fmt.Errorf("provider parameter %q is required", providerParameterKeyAccounts)
	}

	return nil
}
