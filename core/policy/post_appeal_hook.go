package policy

import "github.com/goto/guardian/pkg/http"

// PostAppealHookConfigHTTP defines HTTP configuration for post appeal hooks
// Similar to AppealMetadataSourceConfigHTTP
type PostAppealHookConfigHTTP struct {
	http.HTTPClientConfig `mapstructure:",squash"`
	AllowFailed           bool `mapstructure:"allow_failed,omitempty" json:"allow_failed,omitempty" yaml:"allow_failed,omitempty"`
}
