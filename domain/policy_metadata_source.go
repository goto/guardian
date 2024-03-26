package domain

import (
	"encoding/json"
	"fmt"
	"reflect"
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

func (c *AppealMetadataSource) EvaluateValue(params map[string]interface{}) (interface{}, error) {
	return c.evaluateValue(c.Value, params)
}

func (c *AppealMetadataSource) evaluateValue(value interface{}, params map[string]interface{}) (interface{}, error) {
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.String:
		if strings.Contains(v.String(), "$appeal") || strings.Contains(v.String(), "$response") {
			result, err := evaluator.Expression(v.String()).EvaluateWithVars(params)
			if err != nil {
				return nil, err
			}
			return result, nil
		}
		return value, nil
	case reflect.Map:
		mapResult := map[string]interface{}{}
		for _, key := range v.MapKeys() {
			val := v.MapIndex(key).Interface()
			processedVal, err := c.evaluateValue(val, params)
			if err != nil {
				return nil, err
			}
			mapResult[key.String()] = processedVal
		}
		return mapResult, nil
	case reflect.Slice:
		arrayResult := make([]interface{}, v.Len())
		for i := 0; i < v.Len(); i++ {
			val := v.Index(i).Interface()
			processedVal, err := c.evaluateValue(val, params)
			if err != nil {
				return nil, err
			}
			arrayResult[i] = processedVal
		}
		return arrayResult, nil
	default:
		return v.Interface(), nil
	}
}
