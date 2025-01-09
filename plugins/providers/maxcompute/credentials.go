package maxcompute

import (
	"errors"

	"github.com/goto/guardian/domain"
)

type credentials struct {
	AccessKeyID     string   `mapstructure:"access_key_id" json:"access_key_id"`
	AccessKeySecret string   `mapstructure:"access_key_secret" json:"access_key_secret"`
	RAMRole         string   `mapstructure:"ram_role" json:"ram_role"`
	RegionID        string   `mapstructure:"region_id" json:"region_id"`
	ProjectName     string   `mapstructure:"project_name" json:"project_name"`
	ExcludedSchemas []string `mapstructure:"excluded_schemas" json:"excluded_schemas"`
}

func (c credentials) validate() error {
	if c.AccessKeyID == "" {
		return errors.New("access_key_id is required")
	}
	if c.AccessKeySecret == "" {
		return errors.New("access_key_secret is required")
	}
	if c.RegionID == "" {
		return errors.New("region_id is required")
	}
	if c.ProjectName == "" {
		return errors.New("project_name is required")
	}
	excludedSchemasCheck := make(map[string]struct{})
	for _, schema := range c.ExcludedSchemas {
		if schema == "" {
			return errors.New("excluded_schemas contain empty value")
		}
		if _, ok := excludedSchemasCheck[schema]; ok {
			return errors.New("excluded_schemas contain duplicate value")
		}
		excludedSchemasCheck[schema] = struct{}{}
	}
	return nil
}

func (c *credentials) encrypt(encryptor domain.Encryptor) error {
	encryptedAccessKeySecret, err := encryptor.Encrypt(c.AccessKeySecret)
	if err != nil {
		return err
	}

	c.AccessKeySecret = encryptedAccessKeySecret
	return nil
}

func (c *credentials) decrypt(decryptor domain.Decryptor) error {
	decryptedAccessKeySecret, err := decryptor.Decrypt(c.AccessKeySecret)
	if err != nil {
		return err
	}

	c.AccessKeySecret = decryptedAccessKeySecret
	return nil
}
