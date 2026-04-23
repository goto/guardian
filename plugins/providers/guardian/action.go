package guardian

import (
	"fmt"
)

const (
	resourceTypeAction  = "action"
	resourceTypeOptimus = "optimus"

	providerParameterKeyMetadata = "metadata"
)

type RequiredField struct {
	Key         string `json:"key" mapstructure:"key" yaml:"key"`
	Description string `json:"description,omitempty" mapstructure:"description" yaml:"description,omitempty"`
}

type ActionMetadata struct {
	RequiredFields []RequiredField `json:"required_fields,omitempty" mapstructure:"required_fields" yaml:"required_fields,omitempty"`
}

func (m *ActionMetadata) Validate() error {
	for i, rf := range m.RequiredFields {
		if rf.Key == "" {
			return fmt.Errorf("required_field at index %d is missing key", i)
		}
	}
	return nil
}
