package maxcompute

import (
	"fmt"
	"slices"
	"strings"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/utils"
	"github.com/mitchellh/mapstructure"
)

const (
	sourceName              = "maxcompute"
	tableFetchMaxItem int32 = 100

	accountTypeRAMUser = "ram_user"
	accountTypeBotUser = "bot_user"
	accountTypeRAMRole = "ram_role"

	resourceTypeProject = "project"
	resourceTypeSchema  = "schema"
	resourceTypeTable   = "table"

	parameterRAMRoleKey = "ram_role"

	projectPermissionMember = "member"
)

var (
	validResourceTypes = []string{resourceTypeProject, resourceTypeSchema, resourceTypeTable}

	// https://www.alibabacloud.com/help/en/maxcompute/user-guide/maxcompute-permissions
	validTableActions = []string{"describe", "select", "alter", "update", "drop", "showhistory", "all"}
)

type config struct {
	*domain.ProviderConfig
}

func (c *config) getCredentials() (*credentials, error) {
	if creds, ok := c.Credentials.(credentials); ok { // parsed
		return &creds, nil
	} else if mapCreds, ok := c.Credentials.(map[string]interface{}); ok { // not parsed
		var creds credentials
		if err := mapstructure.Decode(mapCreds, &creds); err != nil {
			return nil, fmt.Errorf("unable to decode credentials: %w", err)
		}
		return &creds, nil
	}

	return nil, fmt.Errorf("invalid credentials type: %T", c.Credentials)
}

func (c *config) validate() error {
	// validate credentials
	if c.Credentials == nil {
		return fmt.Errorf("credentials is required")
	}
	creds, err := c.getCredentials()
	if err != nil {
		return err
	}
	if err := creds.validate(); err != nil {
		return fmt.Errorf("invalid credentials: %w", err)
	}

	// validate resource config
	for _, rc := range c.Resources {
		if !utils.ContainsString(validResourceTypes, rc.Type) {
			return fmt.Errorf("invalid resource type: %q", rc.Type)
		}

		for _, role := range rc.Roles {
			if len(role.Permissions) == 0 {
				return fmt.Errorf("permissions are missing for role: %q", role.Name)
			}
			for _, permission := range role.Permissions {
				permissionStr, ok := permission.(string)
				if !ok {
					return fmt.Errorf("unexpected permission type: %T, expected: string", permission)
				}

				switch rc.Type {
				case resourceTypeTable:
					if !utils.ContainsString(validTableActions, strings.ToLower(permissionStr)) {
						return fmt.Errorf("invalid permission %q for table resource", permissionStr)
					}
				}
			}
		}
	}

	// validate parameters
	for _, param := range c.Parameters {
		if !slices.Contains([]string{parameterRAMRoleKey}, param.Key) {
			return fmt.Errorf("parameter key %q is not supported", param.Key)
		}
	}

	return nil
}
