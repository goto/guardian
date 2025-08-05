package shield

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/goto/guardian/domain"
	"github.com/mitchellh/mapstructure"
)

const (
	RoleMember = "users"
	RoleAdmin  = "admins"

	AccountTypeUser = "user"
)

type Credentials struct {
	Host          string `json:"host" mapstructure:"host" validate:"required"`
	AuthHeader    string `json:"auth_header" mapstructure:"auth_header" validate:"required"`
	AuthEmail     string `json:"auth_email" mapstructure:"auth_email" validate:"required"`
	ClientVersion string `json:"client_version" mapstructure:"client_version"`
}

type Permission string

type Config struct {
	ProviderConfig *domain.ProviderConfig
	valid          bool
	validator      *validator.Validate
}

func NewConfig(pc *domain.ProviderConfig) *Config {
	return &Config{
		ProviderConfig: pc,
		validator:      validator.New(),
	}
}

func (c *Config) ParseAndValidate(dynamicResourceTypes []string) error {
	return c.parseAndValidate(dynamicResourceTypes)
}

func (c *Config) parseAndValidate(listOfDynamicResourceType []string) error {
	if c.valid {
		return nil
	}

	validationErrors := []error{}

	if credentials, err := c.validateCredentials(c.ProviderConfig.Credentials); err != nil {
		validationErrors = append(validationErrors, err)
	} else {
		c.ProviderConfig.Credentials = credentials
	}

	for _, r := range c.ProviderConfig.Resources {
		if err := c.validateResourceConfig(r, listOfDynamicResourceType); err != nil {
			validationErrors = append(validationErrors, err)
		}
	}

	if len(validationErrors) > 0 {
		errorStrings := []string{}
		for _, err := range validationErrors {
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

func (c *Config) validateResourceConfig(resource *domain.ResourceConfig, dynamicResourceTypes []string) error {
	resourceTypes := append([]string{ResourceTypeTeam, ResourceTypeProject, ResourceTypeOrganization}, dynamicResourceTypes...)
	resourceTypeValidation := fmt.Sprintf("oneof=%s", strings.Join(resourceTypes, " "))
	if err := c.validator.Var(resource.Type, resourceTypeValidation); err != nil {
		return err
	}

	for _, role := range resource.Roles {
		for i, permission := range role.Permissions {
			if permissionConfig, err := c.validatePermission(resource.Type, permission); err != nil {
				return err
			} else {
				role.Permissions[i] = permissionConfig
			}
		}
	}

	return nil
}

func (c *Config) validatePermission(resourceType string, value interface{}) (*Permission, error) {
	permissionConfig, ok := value.(string)
	if !ok {
		return nil, ErrInvalidPermissionConfig
	}

	var pc Permission
	if err := mapstructure.Decode(permissionConfig, &pc); err != nil {
		return nil, err
	}

	var nameValidation string
	if resourceType == ResourceTypeTeam {
		nameValidation = "oneof=users admins member manager"
	} else if resourceType == ResourceTypeProject {
		nameValidation = "oneof=admins owner"
	} else if resourceType == ResourceTypeOrganization {
		nameValidation = "oneof=admins owner"
	}

	if err := c.validator.Var(pc, nameValidation); err != nil {
		return nil, err
	}

	return &pc, nil
}
