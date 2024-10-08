package notifiers

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/plugins/notifiers/lark"
	"github.com/goto/guardian/plugins/notifiers/slack"
)

func TestNewSlackConfig(t *testing.T) {
	type args struct {
		config *Config
	}
	tests := []struct {
		name    string
		args    args
		want    *slack.Config
		wantErr bool
	}{
		{
			name: "should return error when no access token or workspaces are provided",
			args: args{
				config: &Config{
					Provider: ProviderTypeSlack,
				},
			},
			want:    nil,
			wantErr: true,
		}, {
			name: "should return error when both access token and workspaces are provided",
			args: args{
				config: &Config{
					Provider:    ProviderTypeSlack,
					AccessToken: "foo",
					SlackConfig: SlackConfig{
						"workspaces": []slack.SlackWorkspace{
							{
								WorkspaceName: "default",
								AccessToken:   "bar",
								Criteria:      "1==1",
							},
						},
					},
				},
			},
			want:    nil,
			wantErr: true,
		}, {
			name: "should return slack config when access token is provided",
			args: args{
				config: &Config{
					Provider:    ProviderTypeSlack,
					AccessToken: "foo",
				},
			},
			want: &slack.Config{
				Workspaces: []slack.SlackWorkspace{
					{
						WorkspaceName: "default",
						AccessToken:   "foo",
						Criteria:      "1==1",
					},
				},
			},
			wantErr: false,
		}, {
			name: "should return slack config when workspaces are provided",
			args: args{
				config: &Config{
					Provider: ProviderTypeSlack,
					SlackConfig: SlackConfig{
						"workspaces": []slack.SlackWorkspace{
							{
								WorkspaceName: "A",
								AccessToken:   "foo",
								Criteria:      "$email contains '@abc'",
							},
							{
								WorkspaceName: "B",
								AccessToken:   "bar",
								Criteria:      "$email contains '@xyz'",
							},
						},
					},
				},
			},
			want: &slack.Config{
				Workspaces: []slack.SlackWorkspace{
					{
						WorkspaceName: "A",
						AccessToken:   "foo",
						Criteria:      "$email contains '@abc'",
					},
					{
						WorkspaceName: "B",
						AccessToken:   "bar",
						Criteria:      "$email contains '@xyz'",
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSlackConfig(tt.args.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSlackConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSlackConfig() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewSlackLarkConfig(t *testing.T) {
	type args struct {
		config Config
	}
	tests := []struct {
		name    string
		args    args
		want    *lark.Config
		wantErr bool
	}{
		{
			name: "should return lark config when clientid is provided",
			args: args{
				config: Config{
					Provider:     "lark",
					AccessToken:  "",
					ClientID:     "foo",
					ClientSecret: "foo",
					Criteria:     "$email contains '@gojek'",
				},
			},
			want: &lark.Config{
				Workspace: lark.LarkWorkspace{
					WorkspaceName: "lark",
					ClientID:      "foo",
					ClientSecret:  "foo",
					Criteria:      "$email contains '@gojek'",
				},
				Messages: domain.NotificationMessages{},
			},
			wantErr: false,
		},
		{
			name: "should return error when no Client id or workspaces are provided",
			args: args{
				config: Config{
					Provider:     "provider",
					AccessToken:  "config.Notifier.AccessToken",
					ClientID:     "",
					ClientSecret: "",
					Criteria:     ".send_to_slack == true",
				},
			},
			want:    nil,
			wantErr: true,
		}, {
			name: "should return error when both Client id and workspaces are provided",
			args: args{
				config: Config{
					Provider:     "provider",
					AccessToken:  "config.Notifier.AccessToken",
					ClientID:     "",
					ClientSecret: "",
					Criteria:     ".send_to_slack == true",
				},
			},
			want:    nil,
			wantErr: true,
		}, {
			name: "should return lark config when workspaces are provided",
			args: args{
				config: Config{
					Provider:     "provider",
					AccessToken:  "config.Notifier.AccessToken",
					ClientID:     "foo",
					ClientSecret: "foo",
					Criteria:     ".send_to_slack == true",
				},
			},
			want: &lark.Config{
				Workspace: lark.LarkWorkspace{
					WorkspaceName: "provider",
					ClientID:      "foo",
					ClientSecret:  "foo",
					Criteria:      ".send_to_slack == true",
				},
				Messages: domain.NotificationMessages{},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			got, err := getLarkConfig(&tt.args.config, domain.NotificationMessages{})

			if (err != nil) != tt.wantErr {
				t.Errorf("NewLarkConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewLarkConfig() got = %v, want %v", got, tt.want)
			}

		})
	}
}
func TestNotify(t *testing.T) {
	var errs []error
	type fields struct {
		clients []Client
		configs []Config
	}
	type args struct {
		ctx          context.Context
		notification []domain.Notification
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []error
	}{
		{
			name: "should return no errors when notifications are empty",
			fields: fields{
				clients: []Client{},
				configs: []Config{},
			},
			args: args{
				ctx:          context.Background(),
				notification: []domain.Notification{},
			},
			want: errs,
		},
		{
			name: "should return error when criteria does not evaluate to boolean",
			fields: fields{
				clients: []Client{&mockClient{}},
				configs: []Config{
					{
						Criteria: "1 + 1",
					},
				},
			},
			args: args{
				ctx: context.Background(),
				notification: []domain.Notification{
					{User: "test@example.com"},
				},
			},
			want: []error{fmt.Errorf("notifier expression did not evaluate to a boolean: 1 + 1")},
		},
		{
			name: "should notify client when criteria evaluates to true",
			fields: fields{
				clients: []Client{&mockClient{}},
				configs: []Config{
					{
						Criteria: "1 == 1",
					},
				},
			},
			args: args{
				ctx: context.Background(),
				notification: []domain.Notification{
					{User: "test@example.com"},
				},
			},
			want: errs,
		},
		{
			name: "should not notify client when criteria evaluates to false",
			fields: fields{
				clients: []Client{&mockClient{}},
				configs: []Config{
					{
						Criteria: "1 == 2",
					},
				},
			},
			args: args{
				ctx: context.Background(),
				notification: []domain.Notification{
					{User: "test@example.com"},
				},
			},
			want: errs,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &NotifyManager{
				clients: tt.fields.clients,
				configs: tt.fields.configs,
			}
			fmt.Println()
			if got := m.Notify(tt.args.ctx, tt.args.notification); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Notify() = %v, want %v", got, tt.want)
			}
		})
	}
}

type mockClient struct{}

func (m *mockClient) Notify(ctx context.Context, notifications []domain.Notification) []error {
	return nil
}
