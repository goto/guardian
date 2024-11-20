package alicloudiam

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/go-playground/validator/v10"
	"github.com/goto/guardian/domain"
	"github.com/mitchellh/mapstructure"
)

const (
	AccountTypeRamUser = "ramUser"
	AccountTypeRamRole = "ramRole"
)

type Credentials struct {
	AccessKeyID     string `mapstructure:"access_key_id" json:"access_key_id" validate:"required,base64"`
	AccessKeySecret string `mapstructure:"access_key_secret" json:"access_key_secret" validate:"required,base64"`
	RoleToAssume    string `mapstructure:"role_to_assume" json:"role_to_assume,omitempty"`
	ResourceName    string `mapstructure:"resource_name" json:"resource_name" validate:"required"`
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
	for i, rc := range c.ProviderConfig.Resources {
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

		// Validate resource role
		if len(rc.Roles) == 0 {
			return fmt.Errorf("role at resource '%v' is empty", rc.Type)
		}

		uniqueRoleId := make(map[string]bool)
		for j, role := range rc.Roles {
			// Validate unique resource role
			if _, exist := uniqueRoleId[role.ID]; exist {
				return fmt.Errorf("role id '%v' at resource '%v' is duplicate", role.ID, rc.Type)
			}
			uniqueRoleId[role.ID] = true

			// Validate permission
			if len(role.Permissions) == 0 {
				return fmt.Errorf("role permission at resource '%v' and role id '%v' is empty", rc.Type, role.ID)
			}
			for _, perm := range role.GetOrderedPermissions() {
				if perm == "" {
					return fmt.Errorf("role permission at resource '%v' and role id '%v' has contain empty value", rc.Type, role.ID)
				}
			}

			// Set default role type to system when role type is empty
			if role.Type == "" {
				c.ProviderConfig.Resources[i].Roles[j].Type = PolicyTypeSystem
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

func (c *Config) validatePermissions(ctx context.Context, resource *domain.ResourceConfig, client AliCloudIamClient) error {
	const maxFetchItem int32 = 1000

	systemPolicies, err := client.GetAllPoliciesByType(ctx, PolicyTypeSystem, maxFetchItem)
	if err != nil {
		return err
	}

	customPolicies, err := client.GetAllPoliciesByType(ctx, PolicyTypeCustom, maxFetchItem)
	if err != nil {
		return err
	}

	for _, role := range resource.Roles {
		for _, perm := range role.GetOrderedPermissions() {
			switch role.Type {
			case PolicyTypeSystem:
				valid := false
				for _, policy := range systemPolicies {
					if *policy.PolicyName == perm {
						valid = true
						break
					}
				}
				if !valid {
					return fmt.Errorf("role permission '%v' with type '%v' at resource '%v' and role id '%v' is invalid", perm, PolicyTypeSystem, resource.Type, role.ID)
				}
			case PolicyTypeCustom:
				valid := false
				for _, policy := range customPolicies {
					if *policy.PolicyName == perm {
						valid = true
						break
					}
				}
				if !valid {
					return fmt.Errorf("role permission '%v' with type '%v' at resource '%v' and role id '%v' is invalid", perm, PolicyTypeCustom, resource.Type, role.ID)
				}
			default:
				return ErrInvalidPolicyType
			}
		}
	}

	return nil
}
