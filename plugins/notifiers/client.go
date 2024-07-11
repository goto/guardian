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
	"github.com/mitchellh/mapstructure"

	"github.com/goto/guardian/domain"
)

type Client interface {
	Notify(context.Context, []domain.Notification) []error
}

type NotifyManager struct {
	clients []Client
}

func (m *NotifyManager) Notify(ctx context.Context, notification []domain.Notification) {
	for _, client := range m.clients {
		client.Notify(ctx, notification)
	}
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

type ClientConfig map[string]interface {
	// AccessToken  string `mapstructure:"access_token"`
	// ClientId     string `mapstructure:"client_id"`
	// ClientSecret string `mapstructure:"client_secret"`
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
	// custom messages
	Messages domain.NotificationMessages
}

type ConfigMultiClient struct {
	Notifiers map[string]Notifier `mapstructure:"notifiers"`
	// custom messages
	Messages domain.NotificationMessages
}
type Notifier struct {
	Provider     string `mapstructure:"provider"`
	AccessToken  string `mapstructure:"access_token,omitempty"`
	ClientID     string `mapstructure:"client_id,omitempty"`
	ClientSecret string `mapstructure:"client_id,omitempty"`
	Criteria     string `mapstructure:"criteria"`
}

func NewMultiClient(config *ConfigMultiClient, logger log.Logger) (NotifyManager, error) {
	fmt.Println("new client multi")
	fmt.Println(config.Notifiers)
	notifyManager := &NotifyManager{}
	for key, notifier := range config.Notifiers {
		fmt.Printf("Key: %s, Value: %+v\n", key, notifier)
		if notifier.Provider == ProviderTypeSlack {

			httpClient := &http.Client{Timeout: 10 * time.Second}

			slackConfig, err := GetSlackConfig(&notifier, config.Messages)
			if err != nil {
				fmt.Println("lark send config 2" + notifier.Provider + err.Error())

			} else {
				slackClient := slack.NewNotifier(slackConfig, httpClient, logger)
				notifyManager.AddClient(slackClient)
			}

		}
		if notifier.Provider == ProviderTypeLark {

			httpClient := &http.Client{Timeout: 10 * time.Second}

			larkConfig, err := GetLarkConfig(&notifier, config.Messages)
			if err != nil {
				fmt.Println("lark send config 2" + notifier.Provider + err.Error())

			} else {
				slackClient := lark.NewNotifier(larkConfig, httpClient, logger)
				notifyManager.AddClient(slackClient)
			}

		}

	}

	return *notifyManager, nil

	//return nil, errors.New("invalid notifier provider type")
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

func GetSlackConfig(config *Notifier, messages domain.NotificationMessages) (*slack.Config, error) {
	// validation
	if config.AccessToken == "" {
		return nil, errors.New("slack access token or workSpaceConfig must be provided")
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
			Messages:   messages,
		}
		return slackConfig, nil

	}
	// var workSpaceConfig slack.WorkSpaceConfig

	// slackConfig = &slack.Config{
	// 	Workspaces: workSpaceConfig.Workspaces,
	// 	Messages:   messages,
	// }

	return slackConfig, nil
}

func GetLarkConfig(config *Notifier, messages domain.NotificationMessages) (*lark.Config, error) {
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
		workspaces := []lark.LarkWorkspace{
			{
				WorkspaceName: "default",
				ClientId:      config.ClientID,
				ClientSecret:  config.ClientSecret,
				Criteria:      "1==1",
			},
		}
		larkConfig = &lark.Config{
			Workspaces: workspaces,
			Messages:   messages,
		}
		return larkConfig, nil

	}
	// var workSpaceConfig lark.WorkSpaceConfig
	// if err := config.LarkConfig.Decode(&workSpaceConfig); err != nil {
	// 	return nil, fmt.Errorf("invalid lark workspace config: %w", err)
	// }

	// larkConfig = &lark.Config{
	// 	Workspaces: workSpaceConfig.Workspaces,
	// 	Messages:   config.Messages,
	// }

	return larkConfig, nil
}

// func NewMultiClientConfig(config *ConfigMultiClient) (*multiclient.Config, error) {
// 	// validation
// 	if config.Provider == "" {
// 		return nil, errors.New("multiConfig must be provided")
// 	}
// 	var configg ConfigMultiClient
// 	// Unmarshal YAML into map[string]interface{}
// 	var c map[string]interface{}

// 	// Use mapstructure to decode map into struct
// 	errrr := mapstructure.Decode(c, &configg)
// 	if errrr != nil {
// 		//log.Fatalf("error decoding: %v", errrr)
// 	}
// 	fmt.Println("lark send config 3" + configg.ClientConfig + "multiConfig.Workspaces")
// 	var multiConfig *multiclient.Config
// 	if config.Provider != "" {
// 		workspaces := []multiclient.Workspace{
// 			{
// 				WorkspaceName: "config.Decode()",
// 				ClientId:      "config.Decode()",
// 				Criteria:      "1==1",
// 			},
// 		}
// 		multiConfig = &multiclient.Config{
// 			Workspaces: workspaces,
// 			Messages:   config.Messages,
// 		}

// 		for _, obj := range workspaces {
// 			fmt.Println("lark send config 4 " + obj.ClientId)
// 		}
// 		return multiConfig, nil
// 	}
// 	fmt.Println("lark send config 3" + config.Provider + "multiConfig.Workspaces")
// 	var workSpaceConfig multiclient.WorkSpaceConfig
// 	if err := config.MultiConfig.Decode(&workSpaceConfig); err != nil {
// 		return nil, fmt.Errorf("invalid slack workspace config: %w", err)
// 	}

// 	multiConfig = &multiclient.Config{
// 		Workspaces: workSpaceConfig.Workspaces,
// 		Messages:   config.Messages,
// 	}
// 	fmt.Println("lark send workspace 2 " + "multiConfig.Workspaces")
// 	return multiConfig, nil
// }

func (nm *NotifyManager) AddClient(client Client) {
	nm.clients = append(nm.clients, client)
}
