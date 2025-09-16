package alicloud_sso

import (
	"github.com/goto/guardian/domain"
)

type credentials struct {
	AccessKeyID     string `mapstructure:"access_key_id" json:"access_key_id" validate:"required"`
	AccessKeySecret string `mapstructure:"access_key_secret" json:"access_key_secret" validate:"required"`
	RAMRole         string `mapstructure:"ram_role" json:"ram_role"`
	RegionID        string `mapstructure:"region_id" json:"region_id" validate:"required"`
	DirectoryID     string `mapstructure:"directory_id" json:"directory_id" validate:"required"`
	MainAccountID   string `mapstructure:"main_account_id" json:"main_account_id" validate:"required"`
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
