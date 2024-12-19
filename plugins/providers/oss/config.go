package oss

import (
	"context"
	"fmt"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/utils"
	"github.com/mitchellh/mapstructure"
)

const (
	AccountTypeRAMUser = "ram_user"
	AccountTypeRAMRole = "ram_role"
	resourceTypeBucket = "bucket"
)

var validResourceTypes = []string{resourceTypeBucket}

type config struct {
	*domain.ProviderConfig
	crypto domain.Crypto
}

func NewConfig(pc *domain.ProviderConfig, crypto domain.Crypto) *config {
	return &config{
		ProviderConfig: pc,
		crypto:         crypto,
	}
}

func (c *config) ParseAndValidate() error {
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
				// TODO: validate permissions
				_, ok := permission.(string)
				if !ok {
					return fmt.Errorf("unexpected permission type: %T, expected: string", permission)
				}
			}
		}
	}
	return nil
}

func (c *config) EncryptCredentials(ctx context.Context) error {
	creds, err := c.getCredentials()
	if err != nil {
		return err
	}

	if err := creds.encrypt(c.crypto); err != nil {
		return fmt.Errorf("unable to encrypt credentials: %w", err)
	}

	c.Credentials = creds
	return nil
}

func (c *config) getCredentials() (*Credentials, error) {
	if creds, ok := c.Credentials.(Credentials); ok { // parsed
		return &creds, nil
	} else if mapCreds, ok := c.Credentials.(map[string]interface{}); ok { // not parsed
		var creds Credentials
		if err := mapstructure.Decode(mapCreds, &creds); err != nil {
			return nil, fmt.Errorf("unable to decode credentials: %w", err)
		}
		return &creds, nil
	}

	return nil, fmt.Errorf("invalid credentials type: %T", c.Credentials)
}
