package domain

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/goto/guardian/pkg/evaluator"
)

type AppealMetadataSource struct {
	Name        string      `json:"name" yaml:"name"`
	Description string      `json:"description,omitempty" yaml:"description,omitempty"`
	Type        string      `json:"type" yaml:"type"`
	Config      interface{} `json:"config,omitempty" yaml:"config,omitempty"`
	Value       interface{} `json:"value" yaml:"value"`
}

func (c *AppealMetadataSource) EncryptConfig(enc Encryptor) error {
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

func (c *AppealMetadataSource) DecryptConfig(dec Decryptor) error {
	configStr, ok := c.Config.(string)
	if !ok {
		return fmt.Errorf("invalid config type: %T, expected string", c.Config)
	}
	decryptedConfig, err := dec.Decrypt(string(configStr))
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

func (c *AppealMetadataSource) EvaluateValue(params map[string]interface{}) (interface{}, error) {
	return c.evaluateValue(c.Value, params)
}

func (c *AppealMetadataSource) evaluateValue(value interface{}, params map[string]interface{}) (interface{}, error) {
	switch value := value.(type) {
	case string:
		if strings.HasPrefix(value, "$appeal") || strings.HasPrefix(value, "$response") {
			result, err := evaluator.Expression(value).EvaluateWithVars(params)
			if err != nil {
				return nil, err
			}
			return result, nil
		} else {
			return value, nil
		}
	case map[string]interface{}: // TODO: handle map[string]int and other types
		mapResult := map[string]interface{}{}
		for key, val := range value {
			processedVal, err := c.evaluateValue(val, params)
			if err != nil {
				return nil, err
			}
			mapResult[key] = processedVal
		}
		return mapResult, nil
	case []interface{}: // TODO: handle []int and other types
		arrayResult := make([]interface{}, len(value))
		for i, val := range value {
			processedVal, err := c.evaluateValue(val, params)
			if err != nil {
				return nil, err
			}
			arrayResult[i] = processedVal
		}
		return arrayResult, nil
	default:
		return value, nil
	}
}
