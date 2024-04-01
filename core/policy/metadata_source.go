package policy

import "github.com/goto/guardian/pkg/http"

type AppealMetadataSourceConfigHTTP struct {
	http.HTTPClientConfig `mapstructure:",squash"`
	AllowFailed           bool `mapstructure:"allow_failed,omitempty" json:"allow_failed,omitempty" yaml:"allow_failed,omitempty"`
}
