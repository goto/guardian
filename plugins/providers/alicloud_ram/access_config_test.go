package alicloud_ram

import (
	"context"
	"errors"
	"testing"

	sso "github.com/alibabacloud-go/cloudsso-20210515/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/plugins/providers/alicloud_ram/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ── fake CloudSSO client ─────────────────────────────────────────────────────

type fakeSSOClient struct {
	addFn      func(*sso.AddPermissionPolicyToAccessConfigurationRequest) (*sso.AddPermissionPolicyToAccessConfigurationResponse, error)
	removeFn   func(*sso.RemovePermissionPolicyFromAccessConfigurationRequest) (*sso.RemovePermissionPolicyFromAccessConfigurationResponse, error)
	provFn     func(*sso.ProvisionAccessConfigurationRequest) (*sso.ProvisionAccessConfigurationResponse, error)
	taskFn     func(*sso.GetTaskStatusRequest) (*sso.GetTaskStatusResponse, error)
	listProvFn func(*sso.ListAccessConfigurationProvisioningsRequest) (*sso.ListAccessConfigurationProvisioningsResponse, error)
}

func (f *fakeSSOClient) AddPermissionPolicyToAccessConfiguration(r *sso.AddPermissionPolicyToAccessConfigurationRequest) (*sso.AddPermissionPolicyToAccessConfigurationResponse, error) {
	return f.addFn(r)
}
func (f *fakeSSOClient) RemovePermissionPolicyFromAccessConfiguration(r *sso.RemovePermissionPolicyFromAccessConfigurationRequest) (*sso.RemovePermissionPolicyFromAccessConfigurationResponse, error) {
	return f.removeFn(r)
}
func (f *fakeSSOClient) ProvisionAccessConfiguration(r *sso.ProvisionAccessConfigurationRequest) (*sso.ProvisionAccessConfigurationResponse, error) {
	return f.provFn(r)
}
func (f *fakeSSOClient) GetTaskStatus(r *sso.GetTaskStatusRequest) (*sso.GetTaskStatusResponse, error) {
	return f.taskFn(r)
}
func (f *fakeSSOClient) ListAccessConfigurationProvisionings(r *sso.ListAccessConfigurationProvisioningsRequest) (*sso.ListAccessConfigurationProvisioningsResponse, error) {
	return f.listProvFn(r)
}

// oneProvisionedTarget wires the fake to report a single RD-Account target and a
// provisioning task that immediately succeeds.
func (f *fakeSSOClient) withSuccessfulReprovision(targetID string) *fakeSSOClient {
	f.listProvFn = func(*sso.ListAccessConfigurationProvisioningsRequest) (*sso.ListAccessConfigurationProvisioningsResponse, error) {
		return &sso.ListAccessConfigurationProvisioningsResponse{
			Body: &sso.ListAccessConfigurationProvisioningsResponseBody{
				AccessConfigurationProvisionings: []*sso.ListAccessConfigurationProvisioningsResponseBodyAccessConfigurationProvisionings{
					{TargetId: tea.String(targetID), TargetType: tea.String(targetTypeRDAccount)},
				},
			},
		}, nil
	}
	f.provFn = func(*sso.ProvisionAccessConfigurationRequest) (*sso.ProvisionAccessConfigurationResponse, error) {
		return &sso.ProvisionAccessConfigurationResponse{
			Body: &sso.ProvisionAccessConfigurationResponseBody{
				Tasks: []*sso.ProvisionAccessConfigurationResponseBodyTasks{{TaskId: tea.String("task-1")}},
			},
		}, nil
	}
	f.taskFn = func(*sso.GetTaskStatusRequest) (*sso.GetTaskStatusResponse, error) {
		return &sso.GetTaskStatusResponse{
			Body: &sso.GetTaskStatusResponseBody{
				TaskStatus: &sso.GetTaskStatusResponseBodyTaskStatus{Status: tea.String(taskStatusSuccess)},
			},
		}, nil
	}
	return f
}

func newClientWithFake(fake *fakeSSOClient) *aliCloudRAMClient {
	return &aliCloudRAMClient{
		directoryID:  "d-test",
		newSSOClient: func() (cloudSSOClient, error) { return fake, nil },
	}
}

// ── client-level: GrantAccessToAccessConfig ──────────────────────────────────

func TestGrantAccessToAccessConfig_AddsPolicyAndReprovisions(t *testing.T) {
	var addedType, addedName, addedAC string
	fake := (&fakeSSOClient{
		addFn: func(r *sso.AddPermissionPolicyToAccessConfigurationRequest) (*sso.AddPermissionPolicyToAccessConfigurationResponse, error) {
			addedType = tea.StringValue(r.PermissionPolicyType)
			addedName = tea.StringValue(r.PermissionPolicyName)
			addedAC = tea.StringValue(r.AccessConfigurationId)
			return &sso.AddPermissionPolicyToAccessConfigurationResponse{}, nil
		},
	}).withSuccessfulReprovision("114240524784")
	c := newClientWithFake(fake)

	err := c.GrantAccessToAccessConfig(context.Background(), []string{"AliyunECSReadOnlyAccess"}, "ac-123")

	require.NoError(t, err)
	assert.Equal(t, PolicyTypeSystem, addedType)
	assert.Equal(t, "AliyunECSReadOnlyAccess", addedName)
	assert.Equal(t, "ac-123", addedAC)
}

func TestGrantAccessToAccessConfig_AlreadyExistsIgnored(t *testing.T) {
	fake := (&fakeSSOClient{
		addFn: func(*sso.AddPermissionPolicyToAccessConfigurationRequest) (*sso.AddPermissionPolicyToAccessConfigurationResponse, error) {
			return nil, &tea.SDKError{Code: tea.String("EntityAlreadyExists.PermissionPolicy")}
		},
	}).withSuccessfulReprovision("acc-1")
	c := newClientWithFake(fake)

	err := c.GrantAccessToAccessConfig(context.Background(), []string{"AliyunECSReadOnlyAccess"}, "ac-123")

	require.NoError(t, err)
}

func TestGrantAccessToAccessConfig_AddErrorPropagates(t *testing.T) {
	fake := &fakeSSOClient{
		addFn: func(*sso.AddPermissionPolicyToAccessConfigurationRequest) (*sso.AddPermissionPolicyToAccessConfigurationResponse, error) {
			return nil, &tea.SDKError{Code: tea.String("Throttling")}
		},
	}
	c := newClientWithFake(fake)

	err := c.GrantAccessToAccessConfig(context.Background(), []string{"p"}, "ac-123")

	require.Error(t, err)
}

func TestGrantAccessToAccessConfig_MissingDirectoryID(t *testing.T) {
	c := &aliCloudRAMClient{newSSOClient: func() (cloudSSOClient, error) { return &fakeSSOClient{}, nil }}

	err := c.GrantAccessToAccessConfig(context.Background(), []string{"p"}, "ac-123")

	assert.ErrorIs(t, err, ErrMissingDirectoryID)
}

func TestGrantAccessToAccessConfig_NoProvisionedTargets_NoOp(t *testing.T) {
	added := false
	provisioned := false
	fake := &fakeSSOClient{
		addFn: func(*sso.AddPermissionPolicyToAccessConfigurationRequest) (*sso.AddPermissionPolicyToAccessConfigurationResponse, error) {
			added = true
			return &sso.AddPermissionPolicyToAccessConfigurationResponse{}, nil
		},
		listProvFn: func(*sso.ListAccessConfigurationProvisioningsRequest) (*sso.ListAccessConfigurationProvisioningsResponse, error) {
			return &sso.ListAccessConfigurationProvisioningsResponse{Body: &sso.ListAccessConfigurationProvisioningsResponseBody{}}, nil
		},
		provFn: func(*sso.ProvisionAccessConfigurationRequest) (*sso.ProvisionAccessConfigurationResponse, error) {
			provisioned = true
			return nil, errors.New("should not be called")
		},
	}
	c := newClientWithFake(fake)

	err := c.GrantAccessToAccessConfig(context.Background(), []string{"p"}, "ac-123")

	require.NoError(t, err)
	assert.True(t, added)
	assert.False(t, provisioned, "provision must not run when there are no targets")
}

func TestWaitForTask_Failed(t *testing.T) {
	fake := &fakeSSOClient{
		taskFn: func(*sso.GetTaskStatusRequest) (*sso.GetTaskStatusResponse, error) {
			return &sso.GetTaskStatusResponse{
				Body: &sso.GetTaskStatusResponseBody{
					TaskStatus: &sso.GetTaskStatusResponseBodyTaskStatus{
						Status:        tea.String(taskStatusFailed),
						FailureReason: tea.String("boom"),
					},
				},
			}, nil
		},
	}
	c := newClientWithFake(fake)

	err := c.waitForTask(context.Background(), fake, "task-x")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
}

// ── provider-level routing ───────────────────────────────────────────────────

func testAccessConfigProviderConfig() *domain.ProviderConfig {
	return &domain.ProviderConfig{
		Type: "alicloud_ram",
		URN:  "test-urn",
		Credentials: map[string]interface{}{
			"main_account_id":   "5348956882036640",
			"access_key_id":     "test-key",
			"access_key_secret": "test-secret",
			"directory_id":      "d-test",
		},
		Resources: []*domain.ResourceConfig{
			{
				Type: ResourceTypeAccount,
				Roles: []*domain.Role{
					{
						ID:   "ecs",
						Name: "ecs",
						Permissions: []interface{}{
							map[string]interface{}{"name": "AliyunECSReadOnlyAccess", "type": PolicyTypeSystem},
						},
					},
					{
						ID:   "custom-only",
						Name: "custom-only",
						Permissions: []interface{}{
							map[string]interface{}{"name": "my-custom", "type": PolicyTypeCustom},
						},
					},
				},
			},
		},
	}
}

func accessConfigGrant(role string) domain.Grant {
	return domain.Grant{
		AccountID:   "ac-123",
		AccountType: AccountTypeAccessConfig,
		Role:        role,
		Resource:    &domain.Resource{Type: ResourceTypeAccount, URN: "5348956882036640"},
	}
}

func TestGrantAccess_AccessConfig_RoutesSystemPolicies(t *testing.T) {
	mockClient := mocks.NewAliCloudRAMClient(t)
	p := newTestProvider()
	pc := testAccessConfigProviderConfig()
	p.Clients[pc.URN] = mockClient

	mockClient.EXPECT().
		GrantAccessToAccessConfig(mock.Anything, []string{"AliyunECSReadOnlyAccess"}, "ac-123").
		Return(nil)

	err := p.GrantAccess(context.Background(), pc, accessConfigGrant("ecs"))

	assert.NoError(t, err)
}

func TestRevokeAccess_AccessConfig_RoutesSystemPolicies(t *testing.T) {
	mockClient := mocks.NewAliCloudRAMClient(t)
	p := newTestProvider()
	pc := testAccessConfigProviderConfig()
	p.Clients[pc.URN] = mockClient

	mockClient.EXPECT().
		RevokeAccessFromAccessConfig(mock.Anything, []string{"AliyunECSReadOnlyAccess"}, "ac-123").
		Return(nil)

	err := p.RevokeAccess(context.Background(), pc, accessConfigGrant("ecs"))

	assert.NoError(t, err)
}

func TestGrantAccess_AccessConfig_NoSystemPolicy(t *testing.T) {
	mockClient := mocks.NewAliCloudRAMClient(t)
	p := newTestProvider()
	pc := testAccessConfigProviderConfig()
	p.Clients[pc.URN] = mockClient

	err := p.GrantAccess(context.Background(), pc, accessConfigGrant("custom-only"))

	assert.ErrorIs(t, err, ErrNoSystemPolicyForAccessConfig)
}

func TestGetSystemPolicyNames(t *testing.T) {
	names, err := getSystemPolicyNames([]*Permission{
		{Name: "A", Type: PolicyTypeSystem},
		{Name: "B", Type: PolicyTypeCustom},
		{Name: "C", Type: PolicyTypeSystem},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"A", "C"}, names)

	_, err = getSystemPolicyNames([]*Permission{{Name: "B", Type: PolicyTypeCustom}})
	assert.ErrorIs(t, err, ErrNoSystemPolicyForAccessConfig)
}
