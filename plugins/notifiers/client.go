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
	"github.com/goto/guardian/plugins/notifiers/larkv2"
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
	logger  log.Logger
}

func (m *NotifyManager) Notify(ctx context.Context, notification []domain.Notification) []error {
	var errs []error
	if len(notification) == 0 {
		return errs
	}
	for i, client := range m.clients {
		config := m.configs[i]
		var selected []domain.Notification
		for _, item := range notification {
			value, err := evaluator.Expression(config.Criteria).EvaluateWithVars(map[string]interface{}{"email": item.User})
			if err != nil {
				errs = append(errs, err)
				continue
			}
			match, ok := value.(bool)
			if !ok {
				errs = append(errs, fmt.Errorf("notifier expression did not evaluate to a boolean: %s", config.Criteria))
				continue
			}
			if match {
				selected = append(selected, item)
			}
		}
		if len(selected) > 0 {
			if notifyErrs := client.Notify(ctx, selected); notifyErrs != nil {
				errs = append(errs, notifyErrs...)
			}
		}
	}
	return errs
}

const (
	ProviderTypeSlack  = "slack"
	ProviderTypeLark   = "lark"
	ProviderTypeLarkV2 = "lark_v2"
)

// SlackConfig is a map of workspace name to config
type SlackConfig map[string]interface{}

func (c SlackConfig) Decode(v interface{}) error {
	return mapstructure.Decode(c, v)
}

type Config struct {
	Provider     string `mapstructure:"provider" validate:"omitempty,oneof=slack lark lark_v2"`
	Name         string `mapstructure:"name"`
	ClientID     string `mapstructure:"client_id,omitempty"`
	ClientSecret string `mapstructure:"client_secret,omitempty"`
	Criteria     string `mapstructure:"criteria"`

	// lark_v2: the worker owns Lark application credentials.
	WorkerURL      string `mapstructure:"worker_url"`
	WorkerToken    string `mapstructure:"worker_token"`
	TimeoutSeconds int    `mapstructure:"timeout_seconds"`

	// slack
	AccessToken string      `mapstructure:"access_token" validate:"required_without=SlackConfig"`
	SlackConfig SlackConfig `mapstructure:"slack_config" validate:"required_without=AccessToken,dive"`
	// custom messages
	Messages domain.NotificationMessages
}

func NewMultiClient(notifiers *[]Config, logger log.Logger) (*NotifyManager, error) {
	notifyManager := &NotifyManager{logger: logger}
	for _, notifier := range *notifiers {
		if notifier.Provider == ProviderTypeLarkV2 {
			client, err := newLarkV2Client(&notifier)
			if err != nil {
				return nil, err
			}
			notifyManager.addClient(client)
			notifyManager.addNotifier(notifier)
		}
		if notifier.Provider == ProviderTypeSlack {
			slackConfig, err := NewSlackConfig(&notifier)
			if err != nil {
				return nil, err
			}
			httpClient := &http.Client{Timeout: 10 * time.Second}
			slackClient := slack.NewNotifier(slackConfig, httpClient, logger)
			notifyManager.addClient(slackClient)
			notifyManager.addNotifier(notifier)
		}
		if notifier.Provider == ProviderTypeLark {
			larkConfig, err := getLarkConfig(&notifier, notifier.Messages)
			if err != nil {
				return nil, err
			}
			httpClient := &http.Client{Timeout: 10 * time.Second}
			larkClient := lark.NewNotifier(larkConfig, httpClient, logger)
			notifyManager.addClient(larkClient)
			notifyManager.addNotifier(notifier)
		}
	}

	return notifyManager, nil
}

func NewClient(config *Config, logger log.Logger) (Client, error) {
	if config.Provider == ProviderTypeLarkV2 {
		return newLarkV2Client(config)
	}
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
			ClientID:      config.ClientID,
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

func newLarkV2Client(config *Config) (Client, error) {
	return larkv2.New(larkv2.Config{URL: config.WorkerURL, Token: config.WorkerToken, TimeoutSeconds: config.TimeoutSeconds})
}

// ConfigureCards attaches Guardian's existing DB only to v2; legacy-only servers need no new table.
func (m *NotifyManager) ConfigureCards(ctx context.Context, store larkv2.CardStore, reader larkv2.AppealReader) error {
	checked := false
	for _, client := range m.clients {
		if v2, ok := client.(*larkv2.Notifier); ok {
			if store == nil || reader == nil {
				return errors.New("notification card synchronization requires a store and appeal reader")
			}
			if !checked {
				if err := store.Ready(ctx); err != nil {
					return errors.New("notification card migration is required")
				}
				checked = true
			}
			v2.ConfigureCards(store, reader)
		}
	}
	return nil
}

func (m *NotifyManager) RunCardSync(ctx context.Context) {
	var clients []*larkv2.Notifier
	for _, client := range m.clients {
		if v2, ok := client.(*larkv2.Notifier); ok {
			clients = append(clients, v2)
		}
	}
	if len(clients) == 0 {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		for _, client := range clients {
			if err := client.ReconcileCards(ctx); err != nil && ctx.Err() == nil && m.logger != nil {
				m.logger.Error(ctx, "notification card reconciliation failed")
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
