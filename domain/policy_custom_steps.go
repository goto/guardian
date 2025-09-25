package domain

import (
	"encoding/json"
	"fmt"
)

type CustomSteps struct {
	Type   string      `json:"type" yaml:"type"`
	Config interface{} `json:"config,omitempty" yaml:"config,omitempty"`
}

type CustomStepsResponse struct {
	ApprovalSteps []*Step `json:"approval_steps"`
}

func (c *CustomSteps) EncryptConfig(enc Encryptor) error {
	configStr, err := json.Marshal(c.Config)
	if err != nil {
		return fmt.Errorf("failed to json.Marshal config: %w", err)
	}

	encryptedConfig, err := enc.Encrypt(string(configStr))
	if err != nil {
		return err
	}
	c.Config = encryptedConfig

	return nil
}

func (c *CustomSteps) DecryptConfig(dec Decryptor) error {
	configStr, ok := c.Config.(string)
	if !ok {
		return fmt.Errorf("invalid config type: %T, expected string", c.Config)
	}
	decryptedConfig, err := dec.Decrypt(configStr)
	if err != nil {
		return err
	}

	var cfg interface{}
	if err := json.Unmarshal([]byte(decryptedConfig), &cfg); err != nil {
		return fmt.Errorf("failed to json.Unmarshal config: %w", err)
	}
	c.Config = cfg

	return nil
}
