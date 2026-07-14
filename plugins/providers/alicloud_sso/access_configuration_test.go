package alicloud_sso

import (
	"context"
	"testing"

	sso "github.com/alibabacloud-go/cloudsso-20210515/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/plugins/providers/alicloud_sso/mocks"
)

const (
	testDirectoryID    = "d-00fc2p61test"
	testAccessConfigID = "ac-00jhtfl8test"
	testChildAccountID = "114240524784"
	testSystemPolicy   = "AliyunECSFullAccess"
	testRoleID         = "ecs-admin"
)

func newTestProvider(t *testing.T) (*provider, *mocks.SsoClient) {
	t.Helper()

	enc := mocks.NewEncryptor(t)
	// getCreds decrypts the access key secret; return it unchanged.
	enc.On("Decrypt", mock.Anything).Return("secret", nil).Maybe()

	p := NewProvider(sourceName, enc, log.NewNoop())
	client := &mocks.SsoClient{}
	p.testSSOClient = client
	return p, client
}

func testProviderConfig() *domain.ProviderConfig {
	return &domain.ProviderConfig{
		Type: sourceName,
		URN:  "test-urn",
		Credentials: map[string]interface{}{
			"access_key_id":     "ak",
			"access_key_secret": "enc-secret",
			"region_id":         "ap-southeast-5",
			"directory_id":      testDirectoryID,
		},
		Resources: []*domain.ResourceConfig{
			{
				Type: resourceTypeAccessConfiguration,
				Roles: []*domain.Role{
					{ID: testRoleID, Permissions: []interface{}{testSystemPolicy}},
				},
			},
		},
	}
}

func testGrant() domain.Grant {
	return domain.Grant{
		Role: testRoleID,
		Resource: &domain.Resource{
			Type: resourceTypeAccessConfiguration,
			URN:  testAccessConfigID,
		},
	}
}

func expectReprovisionSuccess(client *mocks.SsoClient) {
	client.On("ListAccessConfigurationProvisionings", mock.Anything).Return(
		&sso.ListAccessConfigurationProvisioningsResponse{
			Body: &sso.ListAccessConfigurationProvisioningsResponseBody{
				AccessConfigurationProvisionings: []*sso.ListAccessConfigurationProvisioningsResponseBodyAccessConfigurationProvisionings{
					{TargetId: tea.String(testChildAccountID), TargetType: tea.String(targetTypeRDAccount)},
				},
			},
		}, nil).Once()

	client.On("ProvisionAccessConfiguration", mock.MatchedBy(func(req *sso.ProvisionAccessConfigurationRequest) bool {
		return tea.StringValue(req.TargetType) == targetTypeRDAccount &&
			tea.StringValue(req.TargetId) == testChildAccountID &&
			tea.StringValue(req.AccessConfigurationId) == testAccessConfigID
	})).Return(&sso.ProvisionAccessConfigurationResponse{
		Body: &sso.ProvisionAccessConfigurationResponseBody{
			Tasks: []*sso.ProvisionAccessConfigurationResponseBodyTasks{{TaskId: tea.String("task-1")}},
		},
	}, nil).Once()

	client.On("GetTaskStatus", mock.Anything).Return(&sso.GetTaskStatusResponse{
		Body: &sso.GetTaskStatusResponseBody{
			TaskStatus: &sso.GetTaskStatusResponseBodyTaskStatus{Status: tea.String(taskStatusSuccess)},
		},
	}, nil).Once()
}

func TestGrantAccess_AccessConfiguration_Success(t *testing.T) {
	p, client := newTestProvider(t)

	client.On("AddPermissionPolicyToAccessConfiguration", mock.MatchedBy(func(req *sso.AddPermissionPolicyToAccessConfigurationRequest) bool {
		return tea.StringValue(req.PermissionPolicyType) == permissionPolicyTypeSystem &&
			tea.StringValue(req.PermissionPolicyName) == testSystemPolicy &&
			tea.StringValue(req.AccessConfigurationId) == testAccessConfigID &&
			tea.StringValue(req.DirectoryId) == testDirectoryID
	})).Return(&sso.AddPermissionPolicyToAccessConfigurationResponse{}, nil).Once()
	expectReprovisionSuccess(client)

	err := p.GrantAccess(context.Background(), testProviderConfig(), testGrant())

	require.NoError(t, err)
	client.AssertExpectations(t)
}

func TestGrantAccess_AccessConfiguration_AlreadyExistsIgnored(t *testing.T) {
	p, client := newTestProvider(t)

	client.On("AddPermissionPolicyToAccessConfiguration", mock.Anything).Return(
		nil, &tea.SDKError{Code: tea.String("EntityAlreadyExists.PermissionPolicy")}).Once()
	expectReprovisionSuccess(client)

	err := p.GrantAccess(context.Background(), testProviderConfig(), testGrant())

	require.NoError(t, err)
	client.AssertExpectations(t)
}

func TestGrantAccess_AccessConfiguration_AddErrorPropagates(t *testing.T) {
	p, client := newTestProvider(t)

	client.On("AddPermissionPolicyToAccessConfiguration", mock.Anything).Return(
		nil, &tea.SDKError{Code: tea.String("Throttling")}).Once()

	err := p.GrantAccess(context.Background(), testProviderConfig(), testGrant())

	require.Error(t, err)
	client.AssertNotCalled(t, "ProvisionAccessConfiguration", mock.Anything)
}

func TestRevokeAccess_AccessConfiguration_Success(t *testing.T) {
	p, client := newTestProvider(t)

	client.On("RemovePermissionPolicyFromAccessConfiguration", mock.MatchedBy(func(req *sso.RemovePermissionPolicyFromAccessConfigurationRequest) bool {
		return tea.StringValue(req.PermissionPolicyType) == permissionPolicyTypeSystem &&
			tea.StringValue(req.PermissionPolicyName) == testSystemPolicy
	})).Return(&sso.RemovePermissionPolicyFromAccessConfigurationResponse{}, nil).Once()
	expectReprovisionSuccess(client)

	err := p.RevokeAccess(context.Background(), testProviderConfig(), testGrant())

	require.NoError(t, err)
	client.AssertExpectations(t)
}

func TestRevokeAccess_AccessConfiguration_NotExistsIgnored(t *testing.T) {
	p, client := newTestProvider(t)

	client.On("RemovePermissionPolicyFromAccessConfiguration", mock.Anything).Return(
		nil, &tea.SDKError{Code: tea.String("EntityNotExists.PermissionPolicy")}).Once()
	expectReprovisionSuccess(client)

	err := p.RevokeAccess(context.Background(), testProviderConfig(), testGrant())

	require.NoError(t, err)
	client.AssertExpectations(t)
}

func TestReprovision_MultipleTargets(t *testing.T) {
	p, client := newTestProvider(t)

	client.On("ListAccessConfigurationProvisionings", mock.Anything).Return(
		&sso.ListAccessConfigurationProvisioningsResponse{
			Body: &sso.ListAccessConfigurationProvisioningsResponseBody{
				AccessConfigurationProvisionings: []*sso.ListAccessConfigurationProvisioningsResponseBodyAccessConfigurationProvisionings{
					{TargetId: tea.String("acc-1")},
					{TargetId: tea.String("acc-2")},
				},
			},
		}, nil).Once()
	client.On("ProvisionAccessConfiguration", mock.Anything).Return(&sso.ProvisionAccessConfigurationResponse{
		Body: &sso.ProvisionAccessConfigurationResponseBody{
			Tasks: []*sso.ProvisionAccessConfigurationResponseBodyTasks{{TaskId: tea.String("t")}},
		},
	}, nil).Twice()
	client.On("GetTaskStatus", mock.Anything).Return(&sso.GetTaskStatusResponse{
		Body: &sso.GetTaskStatusResponseBody{
			TaskStatus: &sso.GetTaskStatusResponseBodyTaskStatus{Status: tea.String(taskStatusSuccess)},
		},
	}, nil).Twice()

	err := p.reprovisionToAllTargets(context.Background(), client, testDirectoryID, testAccessConfigID)

	require.NoError(t, err)
	client.AssertExpectations(t)
}

func TestWaitForTask_Failed(t *testing.T) {
	p, client := newTestProvider(t)

	client.On("GetTaskStatus", mock.Anything).Return(&sso.GetTaskStatusResponse{
		Body: &sso.GetTaskStatusResponseBody{
			TaskStatus: &sso.GetTaskStatusResponseBodyTaskStatus{
				Status:        tea.String(taskStatusFailed),
				FailureReason: tea.String("boom"),
			},
		},
	}, nil).Once()

	err := p.waitForTask(context.Background(), client, testDirectoryID, "task-x")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
}

func TestGetSystemPolicyNamesFromGrant(t *testing.T) {
	pc := testProviderConfig()

	t.Run("resolves configured policies", func(t *testing.T) {
		names, err := getSystemPolicyNamesFromGrant(pc, testGrant())
		require.NoError(t, err)
		assert.Equal(t, []string{testSystemPolicy}, names)
	})

	t.Run("errors on unknown role", func(t *testing.T) {
		g := testGrant()
		g.Role = "does-not-exist"
		_, err := getSystemPolicyNamesFromGrant(pc, g)
		assert.Error(t, err)
	})

	t.Run("errors on nil resource", func(t *testing.T) {
		g := testGrant()
		g.Resource = nil
		_, err := getSystemPolicyNamesFromGrant(pc, g)
		assert.Error(t, err)
	})
}
