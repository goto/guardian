package policy

import "github.com/goto/guardian/pkg/http"

type AppealMetadataSourceConfigHTTP struct {
	http.HTTPClientConfig `mapstructure:",squash"`
	When                  string `mapstructure:"when,omitempty" json:"when,omitempty" yaml:"when,omitempty"`
	AllowFailed           bool   `mapstructure:"allow_failed,omitempty" json:"allow_failed,omitempty" yaml:"allow_failed,omitempty"`
}
