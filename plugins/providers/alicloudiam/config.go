package alicloudiam

import (
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/goto/guardian/domain"
	"github.com/mitchellh/mapstructure"
	"strings"
)

const (
	AccountTypeRamUser = "ramUser"
	AccountTypeRamRole = "ramRole"
)

type Credentials struct {
	AccessKeyID     string `mapstructure:"access_key_id" json:"access_key_id" validate:"required,len=24"`
	AccessKeySecret string `mapstructure:"access_key_secret" json:"access_key_secret" validate:"required,len=30"`
	ResourceName    string `mapstructure:"resource_name" json:"resource_name" validate:"required"`
}

func (c *Credentials) Encrypt(encryptor domain.Encryptor) error {
	if c == nil {
		return ErrUnableToEncryptNilCredentials
	}

	encryptedAccessKeySecret, err := encryptor.Encrypt(c.AccessKeySecret)
	if err != nil {
		return err
	}

	c.AccessKeySecret = encryptedAccessKeySecret
	return nil
}

func (c *Credentials) Decrypt(decryptor domain.Decryptor) error {
	if c == nil {
		return ErrUnableToDecryptNilCredentials
	}

	decryptedAccessKeySecret, err := decryptor.Decrypt(c.AccessKeySecret)
	if err != nil {
		return err
	}

	c.AccessKeySecret = decryptedAccessKeySecret
	return nil
}

type Config struct {
	ProviderConfig *domain.ProviderConfig
	valid          bool

	crypto    domain.Crypto
	validator *validator.Validate
}

func NewConfig(pc *domain.ProviderConfig, crypto domain.Crypto) *Config {
	return &Config{
		ProviderConfig: pc,
		validator:      validator.New(),
		crypto:         crypto,
	}
}

func (c *Config) ParseAndValidate() error {
	return c.parseAndValidate()
}

func (c *Config) EncryptCredentials() error {
	if err := c.parseAndValidate(); err != nil {
		return err
	}

	credentials, ok := c.ProviderConfig.Credentials.(*Credentials)
	if !ok {
		return ErrInvalidCredentials
	}

	if err := credentials.Encrypt(c.crypto); err != nil {
		return err
	}

	c.ProviderConfig.Credentials = credentials
	return nil
}

func (c *Config) parseAndValidate() error {
	if c.valid {
		return nil
	}

	credentials, err := c.validateCredentials(c.ProviderConfig.Credentials)
	if err != nil {
		return err
	}
	c.ProviderConfig.Credentials = credentials

	if c.ProviderConfig.Resources == nil || len(c.ProviderConfig.Resources) == 0 {
		return errors.New("empty resource config")
	}

	var validationErrors []error
	uniqueResourceTypes := make(map[string]bool)
	for _, rc := range c.ProviderConfig.Resources {
		if _, ok := uniqueResourceTypes[rc.Type]; ok {
			validationErrors = append(validationErrors, fmt.Errorf("duplicate resource type: %q", rc.Type))
		}
		uniqueResourceTypes[rc.Type] = true

		if len(rc.Roles) == 0 {
			validationErrors = append(validationErrors, ErrRolesShouldNotBeEmpty)
		}

		// check for duplicates in roles
		rolesMap := make(map[string]bool, 0)
		for _, role := range rc.Roles {
			if val, ok := rolesMap[role.ID]; ok && val {
				validationErrors = append(validationErrors, fmt.Errorf("duplicate role: %q", role.ID))
				continue
			}
			rolesMap[role.ID] = true
		}
	}

	if len(validationErrors) > 0 {
		errorStrings := make([]string, 0, len(validationErrors))
		for i, err := range validationErrors {
			errorStrings[i] = err.Error()
		}
		return errors.New(strings.Join(errorStrings, "\n"))
	}

	c.valid = true
	return nil
}

func (c *Config) validateCredentials(value interface{}) (*Credentials, error) {
	var credentials Credentials
	if err := mapstructure.Decode(value, &credentials); err != nil {
		return nil, err
	}

	if err := c.validator.Struct(credentials); err != nil {
		return nil, err
	}

	return &credentials, nil
}

func (c *Config) validatePermissions(resource *domain.ResourceConfig, client AliCloudIamClient) error {
	// TODO: add permission validation
	return nil
}
