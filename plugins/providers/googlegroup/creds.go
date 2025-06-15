package googlegroup

import (
	"encoding/base64"
	"fmt"
	"regexp"

	"github.com/goto/guardian/domain"
)

type Credentials struct {
	ServiceAccountKey    string `mapstructure:"service_account_key" yaml:"service_account_key" json:"service_account_key" validate:"required,base64"`
	ImpersonateUserEmail string `mapstructure:"impersonate_user_email" yaml:"impersonate_user_email" json:"impersonate_user_email" validate:"required,email"`
}

func (c *Credentials) validateCreds() error {
	if c.ServiceAccountKey == "" {
		return ErrMissingServiceAccountKey
	}
	if c.ImpersonateUserEmail == "" {
		return ErrMissingImpersonateUserEmail
	}

	// Validate service account key is valid base64
	if _, err := base64.StdEncoding.DecodeString(c.ServiceAccountKey); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidBase64, err)
	}

	// Validate email format
	emailRegex := regexp.MustCompile(emailRegexPattern)
	if !emailRegex.MatchString(c.ImpersonateUserEmail) {
		return ErrInvalidEmailFormat
	}

	return nil
}

func (c *Credentials) encrypt(encryptor domain.Encryptor) error {
	if c == nil {
		return ErrUnableToEncryptNilCredentials
	}

	encryptedCredentials, err := encryptor.Encrypt(c.ServiceAccountKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt service account key: %w", err)
	}

	c.ServiceAccountKey = encryptedCredentials
	return nil
}

func (c *Credentials) decrypt(decryptor domain.Decryptor) error {
	if c == nil {
		return ErrUnableToDecryptNilCredentials
	}

	decryptedCredentials, err := decryptor.Decrypt(c.ServiceAccountKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt service account key: %w", err)
	}

	c.ServiceAccountKey = decryptedCredentials
	return nil
}
