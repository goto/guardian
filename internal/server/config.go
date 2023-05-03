package server

import (
	"errors"
	"fmt"

	"github.com/goto/guardian/internal/store"
	"github.com/goto/guardian/jobs"
	"github.com/goto/guardian/pkg/auth"
	"github.com/goto/guardian/pkg/tracing"
	"github.com/goto/guardian/plugins/notifiers"
	"github.com/goto/salt/config"
)

type DefaultAuth struct {
	HeaderKey string `mapstructure:"header_key" default:"X-Auth-Email"`
}

type Auth struct {
	Provider string        `mapstructure:"provider" default:"default"`
	Default  DefaultAuth   `mapstructure:"default"`
	OIDC     auth.OIDCAuth `mapstructure:"oidc"`
}

type Config struct {
	Port                   int              `mapstructure:"port" default:"8080"`
	EncryptionSecretKeyKey string           `mapstructure:"encryption_secret_key"`
	Notifier               notifiers.Config `mapstructure:"notifier"`
	LogLevel               string           `mapstructure:"log_level" default:"info"`
	DB                     store.Config     `mapstructure:"db"`
	// Deprecated: use Auth.Default.HeaderKey instead note on the AuthenticatedUserHeaderKey
	AuthenticatedUserHeaderKey string                 `mapstructure:"authenticated_user_header_key"`
	AuditLogTraceIDHeaderKey   string                 `mapstructure:"audit_log_trace_id_header_key" default:"X-Trace-Id"`
	Jobs                       map[jobs.Type]jobs.Job `mapstructure:"jobs"`
	Telemetry                  tracing.Config         `mapstructure:"telemetry"`
	Auth                       Auth                   `mapstructure:"auth"`
}

func LoadConfig(configFile string) (Config, error) {
	var cfg Config
	loader := config.NewLoader(config.WithFile(configFile))

	if err := loader.Load(&cfg); err != nil {
		if errors.As(err, &config.ConfigFileNotFoundError{}) {
			fmt.Println(err)
			return cfg, nil
		}
		return Config{}, err
	}

	// keep for backward-compatibility
	if cfg.AuthenticatedUserHeaderKey != "" {
		cfg.Auth.Default.HeaderKey = cfg.AuthenticatedUserHeaderKey
	}

	return cfg, nil
}
