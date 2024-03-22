package domain

type AppealMetadataSource struct {
	Name        string                `json:"name" yaml:"name"`
	Description string                `json:"description,omitempty" yaml:"description,omitempty"`
	Type        string                `json:"type" yaml:"type"`
	Config      *AppealMetadataConfig `json:"config,omitempty" yaml:"config,omitempty"`
	Value       interface{}           `json:"value" yaml:"value"`
}

type AppealMetadataConfig struct {
	URL         string            `json:"url" yaml:"url"`
	AllowFailed bool              `json:"allow_failed,omitempty" yaml:"allow_failed,omitempty"`
	Headers     map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Auth        interface{}       `json:"auth,omitempty" yaml:"auth,omitempty"`
}

type MetadataManager interface {
	ParseMetadataConfig(*AppealMetadataConfig) (SensitiveConfig, error)
}
