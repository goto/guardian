package googlegroup

import (
	"fmt"
	"strings"

	"github.com/goto/guardian/domain"
	"github.com/mitchellh/mapstructure"
	"gorm.io/gorm/utils"
)

var validRoles = []string{roleMember, roleManager, roleOwner}

type config struct {
	*domain.ProviderConfig
}

func (pc *config) GetFilterForResourceType(resourceType string) string {
	for _, resource := range pc.Resources {
		if resource.Type == resourceType {
			return resource.Filter
		}
	}
	return ""
}

func (pc *config) validateConfig() error {
	if pc.Credentials == nil {
		return fmt.Errorf("credentials is required")
	}

	creds, err := pc.getCredentials()
	if err != nil {
		return err
	}

	if err := creds.validateCreds(); err != nil {
		return fmt.Errorf("invalid credentials: %w", err)
	}
	// validate resource config
	if err := pc.validateResourceConfig(); err != nil {
		return err
	}

	return nil
}

func (pc *config) validateResourceConfig() error {
	for _, rc := range pc.Resources {
		if rc.Type != resourceTypeGroup {
			return fmt.Errorf("invalid resource type: %s, %s is the only valid type", rc.Type, resourceTypeGroup)
		}

		for _, role := range rc.Roles {
			if len(role.Permissions) == 0 {
				return fmt.Errorf("permissions are missing for role: %s", role.Name)
			}

			for _, permission := range role.Permissions {
				permissionStr, ok := permission.(string)
				if !ok {
					return fmt.Errorf("unexpected permission type: %T, expected: string", permission)
				}

				if !utils.Contains(validRoles, strings.ToLower(permissionStr)) {
					return fmt.Errorf("invalid permission: %s for resource type: %s", permissionStr, rc.Type)
				}
			}
		}
	}

	return nil
}

func (pc *config) getCredentials() (*Credentials, error) {
	if creds, ok := pc.Credentials.(Credentials); ok {
		return &creds, nil
	} else if mapCreds, ok := pc.Credentials.(map[string]interface{}); ok {
		var creds Credentials
		if err := mapstructure.Decode(mapCreds, &creds); err != nil {
			return nil, fmt.Errorf("unable to decode credentials: %w", err)
		}
		return &creds, nil
	}

	return nil, fmt.Errorf("invalid credentials type: %T", pc.Credentials)
}
