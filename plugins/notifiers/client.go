package notifiers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/plugins/notifiers/lark"
	"github.com/goto/guardian/plugins/notifiers/slack"
	"github.com/goto/guardian/plugins/notifiers/slacklark"
	"github.com/mitchellh/mapstructure"

	"github.com/goto/guardian/domain"
)

type Client interface {
	Notify(context.Context, []domain.Notification) []error
}

const (
	ProviderTypeSlack     = "slack"
	ProviderTypeLark      = "lark"
	ProviderTypeLarkSlack = "slack,lark"
)

// SlackConfig is a map of workspace name to config
type SlackConfig map[string]interface{}

func (c SlackConfig) Decode(v interface{}) error {
	return mapstructure.Decode(c, v)
}

// LarkConfig is a map of workspace name to config
type LarkConfig map[string]interface{}

func (c LarkConfig) Decode(v interface{}) error {
	return mapstructure.Decode(c, v)
}

// LarkConfig is a map of workspace name to config
type SlackLarkConfig map[string]interface{}

func (c SlackLarkConfig) Decode(v interface{}) error {
	return mapstructure.Decode(c, v)
}

type Config struct {
	Provider string `mapstructure:"provider" validate:"omitempty,oneof=slack slack,lark lark"`

	// slack
	AccessToken string      `mapstructure:"access_token" validate:"required_without=SlackConfig"`
	SlackConfig SlackConfig `mapstructure:"slack_config" validate:"required_without=AccessToken,dive"`
	// Lark
	LarkConfig   LarkConfig `mapstructure:"tenant" validate:"required_without=client_id,secret"`
	ClientId     string     `mapstructure:"client_id" validate:"required_without=LarkConfig"`
	ClientSecret string     `mapstructure:"client_secret" validate:"required_without=LarkConfig"`
	// Slack Lark
	SlackLarkConfig SlackLarkConfig `mapstructure:"slackLarkConfig" validate:"required_without=AccessToken,client_id,client_secret"`

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
	if config.Provider == ProviderTypeLark {
		larkConfig, err := NewLarkConfig(config)
		if err != nil {
			return nil, err
		}
		httpClient := &http.Client{Timeout: 10 * time.Second}
		return lark.NewNotifier(larkConfig, httpClient, logger), nil
	}
	if config.Provider == ProviderTypeLarkSlack {
		larkConfig, err := NewLarkConfig(config)
		if err != nil {
			return nil, err
		}
		slackConfig, err2 := NewSlackConfig(config)
		if err2 != nil {
			return nil, err2
		}
		httpClientSlack := &http.Client{Timeout: 10 * time.Second}
		httpClientLark := &http.Client{Timeout: 10 * time.Second}

		return slacklark.NewNotifier(slack.NewNotifier(slackConfig, httpClientSlack, logger), lark.NewNotifier(larkConfig, httpClientLark, logger)), nil
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

func NewLarkConfig(config *Config) (*lark.Config, error) {
	// validation
	if config.ClientId == "" && config.ClientSecret == "" && config.LarkConfig == nil {
		return nil, errors.New("lark clientid or tenantConfig must be provided")
	}
	if config.ClientId != "" && config.ClientSecret == "" && config.LarkConfig != nil {
		return nil, errors.New("lark clientid and tenantConfig cannot be provided at the same time")
	}

	var larkConfig *lark.Config
	if config.ClientId != "" {
		workspaces := []lark.LarkWorkspace{
			{
				WorkspaceName: "default",
				ClientId:      config.ClientId,
				ClientSecret:  config.ClientSecret,
				Criteria:      "1==1",
			},
		}
		larkConfig = &lark.Config{
			Workspaces: workspaces,
			Messages:   config.Messages,
		}
		return larkConfig, nil
	}

	var workSpaceConfig lark.WorkSpaceConfig
	if err := config.LarkConfig.Decode(&workSpaceConfig); err != nil {
		return nil, fmt.Errorf("invalid lark workspace config: %w", err)
	}

	larkConfig = &lark.Config{
		Workspaces: workSpaceConfig.Workspaces,
		Messages:   config.Messages,
	}

	return larkConfig, nil
}
