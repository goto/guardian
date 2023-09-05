package notifiers

import (
	"errors"
	"net/http"
	"time"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/plugins/notifiers/slack"
)

type Client interface {
	Notify([]domain.Notification) []error
}

const (
	ProviderTypeSlack = "slack"
)

type Config struct {
	Provider string `mapstructure:"provider" validate:"omitempty,oneof=slack"`

	// slack
	Workspaces []slack.SlackWorkspace `mapstructure:"workspaces" validate:"required_if=Provider slack,dive"`

	// custom messages
	Messages domain.NotificationMessages
}

func NewClient(config *Config) (Client, error) {
	if config.Provider == ProviderTypeSlack {
		slackConfig := &slack.Config{
			Workspaces: config.Workspaces,
			Messages:   config.Messages,
		}
		httpClient := &http.Client{Timeout: 10 * time.Second}
		return slack.NewNotifier(slackConfig, httpClient), nil
	}

	return nil, errors.New("invalid notifier provider type")
}
