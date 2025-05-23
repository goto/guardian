package bigquery

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/utils"
	"github.com/mitchellh/mapstructure"
)

const (
	DatasetRoleReader = "READER"
	DatasetRoleWriter = "WRITER"
	DatasetRoleOwner  = "OWNER"

	AccountTypeUser           = "user"
	AccountTypeServiceAccount = "serviceAccount"
)

// Credentials is the authentication configuration used by the bigquery client
type Credentials struct {
	ServiceAccountKey string `mapstructure:"service_account_key" json:"service_account_key" validate:"required,base64"`
	ResourceName      string `mapstructure:"resource_name" json:"resource_name" validate:"startswith=projects/"`
}

// Encrypt encrypts BigQuery credentials
func (c *Credentials) Encrypt(encryptor domain.Encryptor) error {
	if c == nil {
		return ErrUnableToEncryptNilCredentials
	}

	encryptedCredentials, err := encryptor.Encrypt(c.ServiceAccountKey)
	if err != nil {
		return err
	}

	c.ServiceAccountKey = encryptedCredentials
	return nil
}

// Decrypt decrypts BigQuery credentials
func (c *Credentials) Decrypt(decryptor domain.Decryptor) error {
	if c == nil {
		return ErrUnableToDecryptNilCredentials
	}

	decryptedCredentials, err := decryptor.Decrypt(c.ServiceAccountKey)
	if err != nil {
		return err
	}

	c.ServiceAccountKey = decryptedCredentials
	return nil
}

func (c Credentials) ProjectID() string {
	return strings.Replace(c.ResourceName, "projects/", "", 1)
}

func ParseCredentials(v interface{}, decryptor domain.Decryptor) (*Credentials, error) {
	var credentials Credentials
	if err := mapstructure.Decode(v, &credentials); err != nil {
		return nil, err
	}

	if err := credentials.Decrypt(decryptor); err != nil {
		return nil, fmt.Errorf("decrypting credentials: %w", err)
	}

	return &credentials, nil
}

// Permission is for mapping role into bigquery permissions
type Permission string

// Config for bigquery provider
type Config struct {
	ProviderConfig *domain.ProviderConfig
	valid          bool

	crypto    domain.Crypto
	validator *validator.Validate

	cachedDatasetGrantableRoles []string
	cachedTableGrantableRoles   []string
}

// NewConfig returns bigquery config struct
func NewConfig(pc *domain.ProviderConfig, crypto domain.Crypto) *Config {
	return &Config{
		ProviderConfig: pc,
		validator:      validator.New(),
		crypto:         crypto,
	}
}

// ParseAndValidate validates bigquery config within provider config and make the interface{} config value castable into the expected bigquery config value
func (c *Config) ParseAndValidate(ctx context.Context) error {
	return c.parseAndValidate(ctx)
}

// EncryptCredentials encrypts the bigquery credentials config
func (c *Config) EncryptCredentials(ctx context.Context) error {
	if err := c.parseAndValidate(ctx); err != nil {
		return err
	}

	credentials, ok := c.ProviderConfig.Credentials.(*Credentials)
	if !ok {
		return ErrInvalidCredentialsType
	}

	if err := credentials.Encrypt(c.crypto); err != nil {
		return err
	}

	c.ProviderConfig.Credentials = credentials
	return nil
}

func (c *Config) parseAndValidate(ctx context.Context) error {
	if c.valid {
		return nil
	}

	credentials, err := c.validateCredentials(c.ProviderConfig.Credentials)
	if err != nil {
		return err
	} else {
		c.ProviderConfig.Credentials = credentials
	}
	projectID := strings.Replace(credentials.ResourceName, "projects/", "", 1)
	client, err := NewBigQueryClient(projectID, []byte(credentials.ServiceAccountKey))
	if err != nil {
		return err
	}

	if c.ProviderConfig.Activity != nil {
		ac := activityConfig{c.ProviderConfig.Activity}
		if err := ac.Validate(); err != nil {
			return fmt.Errorf("validating activity config: %w", err)
		}
	}

	permissionValidationErrors := []error{}

	for _, resource := range c.ProviderConfig.Resources {
		for _, role := range resource.Roles {
			for i, permission := range role.Permissions {
				if permissionConfig, err := c.validatePermission(ctx, permission, resource.Type, client); err != nil {
					permissionValidationErrors = append(permissionValidationErrors, err)
				} else {
					role.Permissions[i] = permissionConfig
				}
			}
		}
	}

	if len(permissionValidationErrors) > 0 {
		errorStrings := []string{}
		for _, err := range permissionValidationErrors {
			errorStrings = append(errorStrings, err.Error())
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

	saKeyJson, err := base64.StdEncoding.DecodeString(credentials.ServiceAccountKey)
	if err != nil {
		return nil, err
	}

	credentials.ServiceAccountKey = string(saKeyJson)

	return &credentials, nil
}

func (c *Config) validatePermission(ctx context.Context, value interface{}, resourceType string, client *bigQueryClient) (*Permission, error) {
	permision, ok := value.(string)
	if !ok {
		return nil, ErrInvalidPermissionConfig
	}

	if resourceType == ResourceTypeDataset {
		if !utils.ContainsString([]string{DatasetRoleReader, DatasetRoleWriter, DatasetRoleOwner}, permision) {
			grantableRoles, err := c.getGrantableRolesForDataset(ctx, client)
			if err != nil {
				if errors.Is(err, ErrEmptyResource) {
					return nil, fmt.Errorf("cannot verify dataset permission: %v", permision)
				}
				return nil, err
			}

			if !utils.ContainsString(grantableRoles, permision) {
				return nil, fmt.Errorf("%v: %v", ErrInvalidDatasetPermission, permision)
			}
		}
	} else if resourceType == ResourceTypeTable {
		roles, err := c.getGrantableRolesForTables(ctx, client)
		if err != nil {
			if err == ErrEmptyResource {
				return nil, ErrCannotVerifyTablePermission
			}
			return nil, err
		}

		if !utils.ContainsString(roles, permision) {
			return nil, fmt.Errorf("%v: %v", ErrInvalidTablePermission, permision)
		}
	} else {
		return nil, ErrInvalidResourceType
	}

	configValue := Permission(permision)
	return &configValue, nil
}

func (c *Config) getGrantableRolesForDataset(ctx context.Context, client *bigQueryClient) ([]string, error) {
	if len(c.cachedDatasetGrantableRoles) > 0 {
		return c.cachedDatasetGrantableRoles, nil
	}

	roles, err := client.getGrantableRolesForDataset(ctx)
	if err != nil {
		return nil, err
	}

	c.cachedDatasetGrantableRoles = roles
	return roles, nil
}

func (c *Config) getGrantableRolesForTables(ctx context.Context, client *bigQueryClient) ([]string, error) {
	if len(c.cachedTableGrantableRoles) > 0 {
		return c.cachedTableGrantableRoles, nil
	}

	roles, err := client.getGrantableRolesForTables(ctx)
	if err != nil {
		return nil, err
	}

	c.cachedTableGrantableRoles = roles
	return roles, nil
}
