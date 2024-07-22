package notifiers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/goto/guardian/pkg/evaluator"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/plugins/notifiers/lark"
	"github.com/goto/guardian/plugins/notifiers/slack"
	"github.com/mitchellh/mapstructure"

	"github.com/goto/guardian/domain"
)

type Client interface {
	Notify(context.Context, []domain.Notification) []error
}

type NotifyManager struct {
	clients []Client
	configs []Config
}

func (m *NotifyManager) Notify(ctx context.Context, notification []domain.Notification) []error {
	var errs []error
	for i, client := range m.clients {
		// evaludate criteria
		config := m.configs[i]
		v, err := evaluator.Expression(config.Criteria).EvaluateWithVars(map[string]interface{}{
			"email": notification[0].User,
		})
		if err != nil {
			errs = append(errs, err)
			continue
		}

		// if the expression evaluates to true, notify the client
		if match, ok := v.(bool); !ok {
			err = fmt.Errorf("notifier expression did not evaluate to a boolean: %s", config.Criteria)
			errs = append(errs, err)
		} else if match {
			if notifyErrs := client.Notify(ctx, notification); notifyErrs != nil {
				errs = append(errs, notifyErrs...)
			}
		}

	}
	return errs
}

const (
	ProviderTypeSlack = "slack"
	ProviderTypeLark  = "lark"
)

// SlackConfig is a map of workspace name to config
type SlackConfig map[string]interface{}

func (c SlackConfig) Decode(v interface{}) error {
	return mapstructure.Decode(c, v)
}

// LarkConfig is a map of workspace name to config
type MultiConfig map[string]interface{}

func (c MultiConfig) Decode(v interface{}) error {
	return mapstructure.Decode(c, v)
}

type Config struct {
	Provider     string `mapstructure:"provider" validate:"omitempty,oneof=slack lark"`
	Name         string `mapstructure:"name"`
	ClientID     string `mapstructure:"client_id,omitempty"`
	ClientSecret string `mapstructure:"client_id,omitempty"`
	Criteria     string `mapstructure:"criteria"`

	// slack
	AccessToken string      `mapstructure:"access_token" validate:"required_without=SlackConfig"`
	SlackConfig SlackConfig `mapstructure:"slack_config" validate:"required_without=AccessToken,dive"`
	// custom messages
	Messages domain.NotificationMessages
}

func NewMultiClient(notifiers *[]Config, logger log.Logger) (*NotifyManager, error) {
	notifyManager := &NotifyManager{}
	for _, notifier := range *notifiers {
		if notifier.Provider == ProviderTypeSlack {

			httpClient := &http.Client{Timeout: 10 * time.Second}

			slackConfig, err := getSlackConfig(&notifier, notifier.Messages)
			if err != nil {
				return nil, err

			} else {
				slackClient := slack.NewNotifier(slackConfig, httpClient, logger)
				notifyManager.addClient(slackClient)
				notifyManager.addNotifier(notifier)
			}

		}
		if notifier.Provider == ProviderTypeLark {

			httpClient := &http.Client{Timeout: 10 * time.Second}

			larkConfig, err := getLarkConfig(&notifier, notifier.Messages)
			if err != nil {
				return nil, err

			} else {
				larkClient := lark.NewNotifier(larkConfig, httpClient, logger)
				notifyManager.addClient(larkClient)
				notifyManager.addNotifier(notifier)
			}

		}

	}

	return notifyManager, nil

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

func getSlackConfig(config *Config, messages domain.NotificationMessages) (*slack.Config, error) {
	// validation
	if config.AccessToken == "" {
		return nil, errors.New("slack access token or workSpaceConfig must be provided")
	}

	var slackConfig *slack.Config
	if config.AccessToken != "" {
		workspaces := []slack.SlackWorkspace{
			{
				WorkspaceName: config.Provider,
				AccessToken:   config.AccessToken,
				Criteria:      config.Criteria,
			},
		}
		slackConfig = &slack.Config{
			Workspaces: workspaces,
			Messages:   messages,
		}
		return slackConfig, nil

	}

	return slackConfig, nil
}

func getLarkConfig(config *Config, messages domain.NotificationMessages) (*lark.Config, error) {
	// validation
	if config.ClientID == "" && config.ClientSecret == "" {
		return nil, errors.New("lark clientid & clientSecret must be provided")
	}
	if config.ClientID == "" && config.ClientSecret != "" {
		return nil, errors.New("lark clientid & clientSecret must be provided")
	}
	if config.ClientID != "" && config.ClientSecret == "" {
		return nil, errors.New("lark clientid & clientSecret must be provided")
	}

	var larkConfig *lark.Config
	if config.ClientID != "" {
		workspace := lark.LarkWorkspace{
			WorkspaceName: config.Provider,
			ClientId:      config.ClientID,
			ClientSecret:  config.ClientSecret,
			Criteria:      config.Criteria,
		}
		larkConfig = &lark.Config{
			Workspace: workspace,
			Messages:  messages,
		}
		return larkConfig, nil

	}

	return larkConfig, nil
}

func (nm *NotifyManager) addClient(client Client) {
	nm.clients = append(nm.clients, client)
}

func (nm *NotifyManager) addNotifier(notifier Config) {
	nm.configs = append(nm.configs, notifier)
}
