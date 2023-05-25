package bigquery

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/utils"
	"github.com/mitchellh/mapstructure"
	"google.golang.org/api/option"
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
	ServiceAccountKey string `mapstructure:"service_account_key" json:"service_account_key" validate:"required"`
	ResourceName      string `mapstructure:"resource_name" json:"resource_name" validate:"startswith=projects/"`
}

func (c Credentials) ProjectID() string {
	return strings.Replace(c.ResourceName, "projects/", "", 1)
}

func ParseCredentials(v interface{}) (*Credentials, error) {
	var credentials Credentials
	if err := mapstructure.Decode(v, &credentials); err != nil {
		return nil, err
	}

	return &credentials, nil
}

// Permission is for mapping role into bigquery permissions
type Permission string

// Config for bigquery provider
type Config struct {
	ProviderConfig *domain.ProviderConfig
	valid          bool

	validator *validator.Validate
}

// NewConfig returns bigquery config struct
func NewConfig(pc *domain.ProviderConfig) *Config {
	return &Config{
		ProviderConfig: pc,
		validator:      validator.New(),
	}
}

// ParseAndValidate validates bigquery config within provider config and make the interface{} config value castable into the expected bigquery config value
func (c *Config) ParseAndValidate() error {
	return c.parseAndValidate()
}

func (c *Config) parseAndValidate() error {
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
	client, err := NewBigQueryClient(projectID, option.WithCredentialsJSON([]byte(credentials.ServiceAccountKey)))
	if err != nil {
		return err
	}

	permissionValidationErrors := []error{}

	for _, resource := range c.ProviderConfig.Resources {
		for _, role := range resource.Roles {
			for i, permission := range role.Permissions {
				if permissionConfig, err := c.validatePermission(permission, resource.Type, client); err != nil {
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

	return &credentials, nil
}

func (c *Config) validatePermission(value interface{}, resourceType string, client *bigQueryClient) (*Permission, error) {
	permision, ok := value.(string)
	if !ok {
		return nil, ErrInvalidPermissionConfig
	}

	if resourceType == ResourceTypeDataset {
		if !utils.ContainsString([]string{DatasetRoleReader, DatasetRoleWriter, DatasetRoleOwner}, permision) {
			return nil, fmt.Errorf("%v: %v", ErrInvalidDatasetPermission, permision)
		}
	} else if resourceType == ResourceTypeTable {
		roles, err := client.getGrantableRolesForTables()
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
