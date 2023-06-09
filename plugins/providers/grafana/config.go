package grafana

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/goto/guardian/domain"
	"github.com/mitchellh/mapstructure"
)

const (
	DashboardRoleViewer = "view"
	DashboardRoleEditor = "edit"
	DashboardRoleAdmin  = "admin"

	AccountTypeUser = "user"
)

type Credentials struct {
	Host     string `json:"host" mapstructure:"host" validate:"required,url"`
	Username string `json:"username" mapstructure:"username" validate:"required"`
	Password string `json:"password" mapstructure:"password" validate:"required"`
}

var permissionCodes = map[string]int{
	"view":  1,
	"edit":  2,
	"admin": 4,
}

type Permission string

type Config struct {
	ProviderConfig *domain.ProviderConfig
	valid          bool

	validator *validator.Validate
}

func NewConfig(pc *domain.ProviderConfig) *Config {
	return &Config{
		ProviderConfig: pc,
		validator:      validator.New(),
	}
}

func (c *Config) ParseAndValidate() error {
	return c.parseAndValidate()
}

func (c *Config) parseAndValidate() error {
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
		if err := c.validateResourceConfig(r); err != nil {
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

func (c *Config) validateResourceConfig(resource *domain.ResourceConfig) error {
	resourceTypeValidation := fmt.Sprintf("oneof=%s %s", ResourceTypeFolder, ResourceTypeDashboard)
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
	if resourceType == ResourceTypeFolder {
		nameValidation = "oneof=view edit admin"
	} else if resourceType == ResourceTypeDashboard {
		nameValidation = "oneof=view edit admin"
	}

	if err := c.validator.Var(pc, nameValidation); err != nil {
		return nil, err
	}

	return &pc, nil
}
