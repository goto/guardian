package notifiers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/goto/guardian/pkg/log"
	"github.com/mitchellh/mapstructure"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/plugins/notifiers/slack"
)

type Client interface {
	Notify(context.Context, []domain.Notification) []error
}

const (
	ProviderTypeSlack = "slack"
)

// SlackConfig is a map of workspace name to config
type SlackConfig map[string]interface{}

func (c SlackConfig) Decode(v interface{}) error {
	return mapstructure.Decode(c, v)
}

type Config struct {
	Provider string `mapstructure:"provider" validate:"omitempty,oneof=slack"`

	// slack
	AccessToken string      `mapstructure:"access_token" validate:"required_without=SlackConfig"`
	SlackConfig SlackConfig `mapstructure:"slack_config" validate:"required_without=AccessToken,dive"`

	// custom messages
	Messages domain.NotificationMessages
}

func NewClient(config *Config, logger log.Logger) (Client, error) {
	if config.Provider == ProviderTypeSlack {
		slackConfig, err := NewSlackConfig(config)
		if err != nil {
			return nil, err
		}

		httpClient := &http.Client{Timeout: 10 * time.Second}

		return slack.NewNotifier(slackConfig, httpClient, logger), nil
	}

	return nil, errors.New("invalid notifier provider type")
}

func NewSlackConfig(config *Config) (*slack.Config, error) {
	// validation
	if config.AccessToken == "" && config.SlackConfig == nil {
		return nil, errors.New("slack access token or workSpaceConfig must be provided")
	}
	if config.AccessToken != "" && config.SlackConfig != nil {
		return nil, errors.New("slack access token and workSpaceConfig cannot be provided at the same time")
	}

	var slackConfig *slack.Config
	if config.AccessToken != "" {
		workspaces := []slack.SlackWorkspace{
			{
				WorkspaceName: "default",
				AccessToken:   config.AccessToken,
				Criteria:      "1==1",
			},
		}
		slackConfig = &slack.Config{
			Workspaces: workspaces,
			Messages:   config.Messages,
		}
		return slackConfig, nil
	}

	var workSpaceConfig slack.WorkSpaceConfig
	if err := config.SlackConfig.Decode(&workSpaceConfig); err != nil {
		return nil, fmt.Errorf("invalid slack workspace config: %w", err)
	}

	slackConfig = &slack.Config{
		Workspaces: workSpaceConfig.Workspaces,
		Messages:   config.Messages,
	}

	return slackConfig, nil
}
