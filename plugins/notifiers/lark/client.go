package lark

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"

	"github.com/goto/guardian/pkg/log"

	"github.com/goto/guardian/utils"

	"github.com/goto/guardian/domain"
)

const (
	larkHost = "https://open.larksuite.com"
)

type tokenResponse struct {
	OK     string `json:"msg"`
	Token  string `json:"tenant_access_token"`
	Code   int    `json:"code"`
	Expire int    `json:"expire"`
}

type Payload struct {
	AppID     string `json:"app_id"`
	AppSecret string `json:"app_secret"`
}

type WorkSpaceConfig struct {
	Workspaces []LarkWorkspace `mapstructure:"workspaces"`
}

type LarkWorkspace struct {
	WorkspaceName string `mapstructure:"workspace" validate:"required"`
	ClientID      string `mapstructure:"client_id" validate:"required"`
	ClientSecret  string `mapstructure:"client_secret" validate:"required"`
	Criteria      string `mapstructure:"criteria" validate:"required"`
}

type Notifier struct {
	workspace           LarkWorkspace
	Messages            domain.NotificationMessages
	httpClient          utils.HTTPClient
	defaultMessageFiles embed.FS
	logger              log.Logger
}

type Config struct {
	Workspace LarkWorkspace
	Messages  domain.NotificationMessages
}

//go:embed templates/*
var defaultTemplates embed.FS

func NewNotifier(config *Config, httpClient utils.HTTPClient, logger log.Logger) *Notifier {
	return &Notifier{
		workspace:           config.Workspace,
		Messages:            config.Messages,
		httpClient:          httpClient,
		defaultMessageFiles: defaultTemplates,
		logger:              logger,
	}
}

func (n *Notifier) Notify(ctx context.Context, items []domain.Notification) []error {
	errs := make([]error, 0)
	for _, item := range items {
		var larkWorkspace *LarkWorkspace
		email := item.User
		labelSlice := utils.MapToSlice(item.Labels)
		larkWorkspace = &n.workspace

		n.logger.Debug(ctx, fmt.Sprintf("%v | sending lark notification to user:%s ", labelSlice, item.User))
		msg, err := ParseMessage(item.Message, n.Messages, n.defaultMessageFiles)
		if err != nil {
			errs = append(errs, fmt.Errorf("%v | error parsing message : %w", labelSlice, err))
			continue
		}

		if err := n.sendMessage(*larkWorkspace, email, msg); err != nil {
			errs = append(errs, fmt.Errorf("%v | error sending message to user:%s in workspace:%s | %w", labelSlice, item.User, larkWorkspace.WorkspaceName, err))
			continue
		}
	}

	return errs
}

func (n *Notifier) sendMessage(workspace LarkWorkspace, email string, messageBlock string) error {
	url := larkHost + "/open-apis/im/v1/messages?receive_id_type=email"
	var messageblockList []interface{}
	if err := json.Unmarshal([]byte(messageBlock), &messageblockList); err != nil {
		return fmt.Errorf("error in parsing message block %s", err)
	}
	var payload map[string]interface{}
	var messages []map[string]interface{}
	err := json.Unmarshal([]byte(messageBlock), &messages)
	for _, message := range messages {

		payload = message
	}
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)

	}
	payload["receive_id"] = email
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	// create tanent_access_token
	token, err := n.findTenantAccessToken(workspace.ClientID, workspace.ClientSecret, workspace)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Type", "application/json")
	_, err = n.sendRequest(req)
	return err
}

func (n *Notifier) findTenantAccessToken(clientId string, clientSecret string, ws LarkWorkspace) (string, error) {
	larkURL := larkHost + "/open-apis/auth/v3/tenant_access_token/internal/"
	payload := Payload{
		AppID:     clientId,
		AppSecret: clientSecret,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, larkURL, bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/json")
	result, err := n.sendRequest(req)
	if err != nil {
		return "", fmt.Errorf("error get tenant access token for workspace: %s - %s", ws.WorkspaceName, err)
	}
	if result.OK != "ok" {
		return "", fmt.Errorf("could not get token for workspace: %s - %s", ws.WorkspaceName, result.OK)
	}
	return result.Token, nil
}

func (n *Notifier) sendRequest(req *http.Request) (*tokenResponse, error) {

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	var result tokenResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if result.OK != "ok" {
		return &result, errors.New(result.OK)
	}
	return &result, nil
}

func getDefaultTemplate(messageType string, defaultTemplateFiles embed.FS) (string, error) {
	content, err := defaultTemplateFiles.ReadFile(fmt.Sprintf("templates/%s.json", messageType))
	if err != nil {
		return "", fmt.Errorf("error finding default template for message type %s - %s", messageType, err)
	}
	return string(content), nil
}

func ParseMessage(message domain.NotificationMessage, templates domain.NotificationMessages, defaultTemplateFiles embed.FS) (string, error) {
	messageTypeTemplateMap := map[string]string{
		domain.NotificationTypeAccessRevoked:            templates.AccessRevoked,
		domain.NotificationTypeAppealApproved:           templates.AppealApproved,
		domain.NotificationTypeAppealRejected:           templates.AppealRejected,
		domain.NotificationTypeApproverNotification:     templates.ApproverNotification,
		domain.NotificationTypeExpirationReminder:       templates.ExpirationReminder,
		domain.NotificationTypeOnBehalfAppealApproved:   templates.OthersAppealApproved,
		domain.NotificationTypeGrantOwnerChanged:        templates.GrantOwnerChanged,
		domain.NotificationTypeNewComment:               templates.NewComment,
		domain.NotificationTypePendingApprovalsReminder: templates.PendingApprovalsReminder,
	}

	messageBlock, ok := messageTypeTemplateMap[message.Type]
	if !ok {
		return "", fmt.Errorf("template not found for message type %s", message.Type)
	}

	if messageBlock == "" {
		defaultMsgBlock, err := getDefaultTemplate(message.Type, defaultTemplateFiles)
		if err != nil {
			return "", err
		}
		messageBlock = defaultMsgBlock
	}
	t, err := template.New("notification_messages").Parse(messageBlock)
	if err != nil {
		return "", err
	}

	var buff bytes.Buffer
	if err := t.Execute(&buff, message.Variables); err != nil {
		return "", err
	}

	return buff.String(), nil
}
