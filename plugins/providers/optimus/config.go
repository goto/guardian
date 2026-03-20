package optimus

import (
	"errors"
	"fmt"

	"github.com/goto/guardian/domain"
	"github.com/mitchellh/mapstructure"
)

const (
	ResourceTypeJob = "job"
)

var (
	ErrMissingCredentials    = errors.New("missing credentials")
	ErrMissingHost           = errors.New("host is required in credentials")
	ErrMissingProjectName    = errors.New("project_name is required in credentials")
	ErrInvalidCredentialType = errors.New("invalid credentials type")
)

var ErrInvalidResourceType = fmt.Errorf("invalid resource type, only %q is supported", ResourceTypeJob)

type credentials struct {
	Host        string `mapstructure:"host"         yaml:"host"         json:"host"`
	ProjectName string `mapstructure:"project_name" yaml:"project_name" json:"project_name"`
}

func (c *credentials) validate() error {
	if c.Host == "" {
		return ErrMissingHost
	}
	if c.ProjectName == "" {
		return ErrMissingProjectName
	}
	return nil
}

func (c *credentials) encrypt(encryptor domain.Encryptor) error {
	if c == nil {
		return ErrMissingCredentials
	}

	if c.Host != "" {
		encryptedHost, err := encryptor.Encrypt(c.Host)
		if err != nil {
			return fmt.Errorf("encrypting host: %w", err)
		}
		c.Host = encryptedHost
	}

	if c.ProjectName != "" {
		encryptedProjectName, err := encryptor.Encrypt(c.ProjectName)
		if err != nil {
			return fmt.Errorf("encrypting project_name: %w", err)
		}
		c.ProjectName = encryptedProjectName
	}

	return nil
}

func (c *credentials) decrypt(decryptor domain.Decryptor) error {
	if c == nil {
		return ErrMissingCredentials
	}

	if c.Host != "" {
		decryptedHost, err := decryptor.Decrypt(c.Host)
		if err != nil {
			return fmt.Errorf("decrypting host: %w", err)
		}
		c.Host = decryptedHost
	}

	if c.ProjectName != "" {
		decryptedProjectName, err := decryptor.Decrypt(c.ProjectName)
		if err != nil {
			return fmt.Errorf("decrypting project_name: %w", err)
		}
		c.ProjectName = decryptedProjectName
	}

	return nil
}

type config struct {
	*domain.ProviderConfig
}

func (c *config) validate() error {

	if c.Credentials == nil {
		return ErrMissingCredentials
	}

	creds, err := c.getCredentials()
	if err != nil {
		return err
	}

	if err := creds.validate(); err != nil {
		return fmt.Errorf("invalid credentials: %w", err)
	}

	if len(c.Resources) == 0 {
		return errors.New("empty resource config")
	}
	for _, rc := range c.Resources {
		if rc.Type != ResourceTypeJob {
			return ErrInvalidResourceType
		}
	}
	return nil
}

func (c *config) getCredentials() (*credentials, error) {
	if creds, ok := c.Credentials.(credentials); ok {
		return &creds, nil
	} else if m, ok := c.Credentials.(map[string]interface{}); ok {
		var creds credentials
		if err := mapstructure.Decode(m, &creds); err != nil {
			return nil, fmt.Errorf("unable to decode credentials: %w", err)
		}
		return &creds, nil
	}
	return nil, fmt.Errorf("%w: %T", ErrInvalidCredentialType, c.Credentials)
}
