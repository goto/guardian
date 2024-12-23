package alicloud_ram

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/bearaujus/bptr"
	"github.com/go-playground/validator/v10"
	"github.com/goto/guardian/domain"
	"github.com/mitchellh/mapstructure"
)

const (
	AccountTypeRamUser = "ramUser"
	AccountTypeRamRole = "ramRole"

	maxFetchItem int32 = 1000
)

type Credentials struct {
	MainAccountID   string `mapstructure:"main_account_id" json:"main_account_id" validate:"required"` // example: 5123xxxxxxxxx
	AccessKeyID     string `mapstructure:"access_key_id" json:"access_key_id" validate:"required,base64"`
	AccessKeySecret string `mapstructure:"access_key_secret" json:"access_key_secret" validate:"required,base64"`
	RAMRole         string `mapstructure:"ram_role" json:"ram_role,omitempty"` // (optional) example: `acs:ram::{MAIN_ACCOUNT_ID}:role/{ROLE_NAME}`
	RegionID        string // (optional) can be empty for using default region id. see: https://www.alibabacloud.com/help/en/cloud-migration-guide-for-beginners/latest/regions-and-zones
}

func (c *Credentials) Encrypt(encryptor domain.Encryptor) error {
	if c == nil {
		return ErrUnableToEncryptNilCredentials
	}

	encryptedAccessKeyID, err := encryptor.Encrypt(c.AccessKeyID)
	if err != nil {
		return err
	}

	encryptedAccessKeySecret, err := encryptor.Encrypt(c.AccessKeySecret)
	if err != nil {
		return err
	}

	c.AccessKeyID = encryptedAccessKeyID
	c.AccessKeySecret = encryptedAccessKeySecret
	return nil
}

func (c *Credentials) Decrypt(decryptor domain.Decryptor) error {
	if c == nil {
		return ErrUnableToDecryptNilCredentials
	}

	decryptedAccessKeyID, err := decryptor.Decrypt(c.AccessKeyID)
	if err != nil {
		return err
	}

	decryptedAccessKeySecret, err := decryptor.Decrypt(c.AccessKeySecret)
	if err != nil {
		return err
	}

	c.AccessKeyID = decryptedAccessKeyID
	c.AccessKeySecret = decryptedAccessKeySecret
	return nil
}

type Permission struct {
	Name string `mapstructure:"name" json:"name" validate:"required"`
	Type string `mapstructure:"type" json:"type" validate:"required,oneof=System Custom"`
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
	if c.valid {
		return nil
	}

	// Validate credentials
	var credentials Credentials
	if err := mapstructure.Decode(c.ProviderConfig.Credentials, &credentials); err != nil {
		return err
	}
	if err := c.validator.Struct(credentials); err != nil {
		return err
	}

	// Decode credentials
	decodedAccessKeyID, err := base64.StdEncoding.DecodeString(credentials.AccessKeyID)
	if err != nil {
		return err
	}

	decodedAccessKeySecret, err := base64.StdEncoding.DecodeString(credentials.AccessKeySecret)
	if err != nil {
		return err
	}
	credentials.AccessKeyID = string(decodedAccessKeyID)
	credentials.AccessKeySecret = string(decodedAccessKeySecret)
	c.ProviderConfig.Credentials = &credentials

	// Validate if resource(s) is present
	if c.ProviderConfig.Resources == nil || len(c.ProviderConfig.Resources) == 0 {
		return ErrEmptyResourceConfig
	}

	uniqueResourceTypes := make(map[string]bool)
	for _, rc := range c.ProviderConfig.Resources {
		// Validate resource type
		var valid bool
		for _, resourceType := range getResourceTypes() {
			if resourceType == rc.Type {
				valid = true
				break
			}
		}
		if !valid {
			return ErrInvalidResourceType
		}

		// Validate unique resource type
		if _, exist := uniqueResourceTypes[rc.Type]; exist {
			return fmt.Errorf("type '%v' at resource is duplicate", rc.Type)
		}
		uniqueResourceTypes[rc.Type] = true

		// Validate empty resource role
		if len(rc.Roles) == 0 {
			return fmt.Errorf("role at resource '%v' is empty", rc.Type)
		}

		uniqueRoleId := make(map[string]bool)
		for _, role := range rc.Roles {
			// Validate unique resource role
			if _, exist := uniqueRoleId[role.ID]; exist {
				return fmt.Errorf("role id '%v' at resource '%v' is duplicate", role.ID, rc.Type)
			}
			uniqueRoleId[role.ID] = true

			// Validate empty permission
			if len(role.Permissions) == 0 {
				return fmt.Errorf("role permission at resource '%v' and role id '%v' is empty", rc.Type, role.ID)
			}
		}
	}
	c.valid = true

	return nil
}

func (c *Config) EncryptCredentials() error {
	if err := c.ParseAndValidate(); err != nil {
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

func (c *Config) validatePermissions(ctx context.Context, resource *domain.ResourceConfig, client AliCloudRAMClient) error {
	systemPolicies, err := client.GetAllPoliciesByType(ctx, PolicyTypeSystem, maxFetchItem)
	if err != nil {
		return err
	}

	customPolicies, err := client.GetAllPoliciesByType(ctx, PolicyTypeCustom, maxFetchItem)
	if err != nil {
		return err
	}

	for _, role := range resource.Roles {
		for _, rawPermission := range role.Permissions {
			var permission Permission
			err = mapstructure.Decode(rawPermission, &permission)
			if err != nil {
				return fmt.Errorf("role permission '%v' at resource '%v' and role id '%v' is invalid format", rawPermission, resource.Type, role.ID)
			}

			err = c.validator.Struct(permission)
			if err != nil {
				return fmt.Errorf("role permission '%v' at resource '%v' and role id '%v' has fail on validation. err: %v", rawPermission, resource.Type, role.ID, err.Error())
			}

			selectedPolicies := systemPolicies
			if permission.Type == PolicyTypeCustom {
				selectedPolicies = customPolicies
			}

			var valid bool
			for _, policy := range selectedPolicies {
				if bptr.ToStringSafe(policy.PolicyName) == permission.Name {
					valid = true
					break
				}
			}

			if !valid {
				return fmt.Errorf("role permission '%v' with type '%v' at resource '%v' and role id '%v' is invalid", permission.Name, permission.Type, resource.Type, role.ID)
			}
		}
	}

	return nil
}
