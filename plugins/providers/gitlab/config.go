package gitlab

import (
	"errors"
	"fmt"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/utils"
	"github.com/mitchellh/mapstructure"
	"github.com/xanzy/go-gitlab"
)

const (
	accountTypeGitlabUserID = "gitlab_user_id"

	resourceTypeProject = "project"
	resourceTypeGroup   = "group"

	// https://docs.gitlab.com/ee/api/members.html#roles
	roleNoAccess      = "no_access"
	roleMinimalAccess = "minimal_access"
	roleGuest         = "guest"
	roleReporter      = "reporter"
	roleDeveloper     = "developer"
	roleMaintainer    = "maintainer"
	roleOwner         = "owner"
)

var (
	validResourceTypes = []string{resourceTypeProject, resourceTypeGroup}
	validGitlabRoles   = []string{
		roleNoAccess,
		roleMinimalAccess,
		roleGuest,
		roleReporter,
		roleDeveloper,
		roleMaintainer,
		roleOwner,
	}
	gitlabRoleMapping = map[string]gitlab.AccessLevelValue{
		roleNoAccess:      gitlab.AccessLevelValue(gitlab.NoPermissions),
		roleMinimalAccess: gitlab.AccessLevelValue(5),
		roleGuest:         gitlab.AccessLevelValue(gitlab.GuestPermissions),
		roleReporter:      gitlab.AccessLevelValue(gitlab.ReporterPermissions),
		roleDeveloper:     gitlab.AccessLevelValue(gitlab.DeveloperPermissions),
		roleMaintainer:    gitlab.AccessLevelValue(gitlab.MaintainerPermissions),
		roleOwner:         gitlab.AccessLevelValue(gitlab.OwnerPermissions),
	}
)

type credentials struct {
	Host        string `mapstructure:"host" yaml:"host" json:"host"`
	AccessToken string `mapstructure:"access_token" yaml:"access_token" json:"access_token"`
}

func (c credentials) validate() error {
	if c.Host == "" {
		return errors.New("host is required")
	}
	if c.AccessToken == "" {
		return errors.New("access_token is required")
	}
	return nil
}

func (c *credentials) encrypt(encryptor domain.Encryptor) error {
	encryptedAccessToken, err := encryptor.Encrypt(c.AccessToken)
	if err != nil {
		return err
	}

	c.AccessToken = encryptedAccessToken
	return nil
}

func (c *credentials) decrypt(decryptor domain.Decryptor) error {
	decryptedAccessToken, err := decryptor.Decrypt(c.AccessToken)
	if err != nil {
		return err
	}

	c.AccessToken = decryptedAccessToken
	return nil
}

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

func (c *config) validateGitlabSpecificConfig() error {
	// validate credentials
	if c.Credentials == nil {
		return fmt.Errorf("missing credentials")
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
			for _, permission := range role.Permissions {
				permissionString, ok := permission.(string)
				if !ok {
					return fmt.Errorf("unexpected permission type: %T, expected: string", permission)
				}
				if !utils.ContainsString(validGitlabRoles, permissionString) {
					return fmt.Errorf("invalid permission: %q", permissionString)
				}
			}
		}
	}

	return nil
}
