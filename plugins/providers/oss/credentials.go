package oss

import (
	"errors"

	"github.com/goto/guardian/domain"
)

type Credentials struct {
	AccessKeyID     string `mapstructure:"access_key_id" json:"access_key_id"`
	AccessKeySecret string `mapstructure:"access_key_secret" json:"access_key_secret"`
	RAMRole         string `mapstructure:"ram_role" json:"ram_role"`
	RegionID        string `mapstructure:"region_id" json:"region_id"`
}

func (c *Credentials) validate() error {
	if c.AccessKeyID == "" {
		return errors.New("access_key_id is required")
	}
	if c.AccessKeySecret == "" {
		return errors.New("access_key_secret is required")
	}
	if c.RegionID == "" {
		return errors.New("region_id is required")
	}
	return nil
}

func (c *Credentials) encrypt(encryptor domain.Encryptor) error {
	encryptedAccessKeySecret, err := encryptor.Encrypt(c.AccessKeySecret)
	if err != nil {
		return err
	}

	c.AccessKeySecret = encryptedAccessKeySecret
	return nil
}

func (c *Credentials) decrypt(decryptor domain.Decryptor) error {
	decryptedAccessKeySecret, err := decryptor.Decrypt(c.AccessKeySecret)
	if err != nil {
		return err
	}

	c.AccessKeySecret = decryptedAccessKeySecret
	return nil
}
