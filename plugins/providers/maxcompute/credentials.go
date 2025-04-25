package maxcompute

import (
	"errors"

	"github.com/goto/guardian/domain"
)

type credentials struct {
	AccessKeyID         string `mapstructure:"access_key_id" json:"access_key_id"`
	AccessKeySecret     string `mapstructure:"access_key_secret" json:"access_key_secret"`
	RAMRole             string `mapstructure:"ram_role" json:"ram_role"`
	RegionID            string `mapstructure:"region_id" json:"region_id"`
	ProjectName         string `mapstructure:"project_name" json:"project_name"`
	SchemaDefaultPolicy string `mapstructure:"schema_default_policy" json:"schema_default_policy"`
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
