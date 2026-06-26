package alicloud_ram

import (
	"context"
	"errors"
	"testing"

	ram "github.com/alibabacloud-go/ram-20150501/v2/client"
	"github.com/bearaujus/bptr"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/plugins/providers/alicloud_ram/mocks"
	"github.com/goto/guardian/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func newTestProvider() *Provider {
	return &Provider{
		typeName: "alicloud_ram",
		Clients:  map[string]AliCloudRAMClient{},
	}
}

func testProviderConfig(resourceType string) *domain.ProviderConfig {
	pc := &domain.ProviderConfig{
		Type: "alicloud_ram",
		URN:  "test-urn",
		Credentials: map[string]interface{}{
			"main_account_id":   "5348956882036640",
			"access_key_id":     "test-key",
			"access_key_secret": "test-secret",
		},
	}
	if resourceType != "" {
		pc.Resources = []*domain.ResourceConfig{
			{
				Type: resourceType,
				Roles: []*domain.Role{
					{
						ID:          STSTrustPolicyRole,
						Name:        STSTrustPolicyRole,
						Permissions: []interface{}{},
					},
				},
			},
		}
	}
	return pc
}

// ── GetResources ─────────────────────────────────────────────────────────────

func TestGetResources_RAMRole_Success(t *testing.T) {
	mockClient := mocks.NewAliCloudRAMClient(t)
	p := newTestProvider()
	pc := testProviderConfig(ResourceTypeRAMRole)
	p.Clients[pc.URN] = mockClient

	roles := []*ram.ListRolesResponseBodyRolesRole{
		{
			RoleName: bptr.FromStringNilAble("DevRole"),
			Arn:      bptr.FromStringNilAble("acs:ram::5348956882036640:role/DevRole"),
		},
		{
			RoleName: bptr.FromStringNilAble("OpsRole"),
			Arn:      bptr.FromStringNilAble("acs:ram::5348956882036640:role/OpsRole"),
		},
	}

	mockClient.EXPECT().GetAllRoles(mock.Anything, maxFetchItem).Return(roles, nil)

	resources, err := p.GetResources(context.Background(), pc)

	assert.NoError(t, err)
	assert.Len(t, resources, 2)
	assert.Equal(t, "DevRole", resources[0].Name)
	assert.Equal(t, "acs:ram::5348956882036640:role/DevRole", resources[0].URN)
	assert.Equal(t, ResourceTypeRAMRole, resources[0].Type)
	assert.Equal(t, pc.URN, resources[0].ProviderURN)
	assert.Equal(t, utils.GetGlobalURN("alicloud_ram_role", "5348956882036640", ResourceTypeRAMRole, "DevRole"), resources[0].GlobalURN)

	assert.Equal(t, "OpsRole", resources[1].Name)
}

func TestGetResources_RAMRole_ClientError(t *testing.T) {
	mockClient := mocks.NewAliCloudRAMClient(t)
	p := newTestProvider()
	pc := testProviderConfig(ResourceTypeRAMRole)
	p.Clients[pc.URN] = mockClient

	mockClient.EXPECT().GetAllRoles(mock.Anything, maxFetchItem).Return(nil, errors.New("api error"))

	resources, err := p.GetResources(context.Background(), pc)

	assert.Error(t, err)
	assert.Nil(t, resources)
}

func TestGetResources_RAMRole_Empty(t *testing.T) {
	mockClient := mocks.NewAliCloudRAMClient(t)
	p := newTestProvider()
	pc := testProviderConfig(ResourceTypeRAMRole)
	p.Clients[pc.URN] = mockClient

	mockClient.EXPECT().GetAllRoles(mock.Anything, maxFetchItem).Return([]*ram.ListRolesResponseBodyRolesRole{}, nil)

	resources, err := p.GetResources(context.Background(), pc)

	assert.NoError(t, err)
	assert.Empty(t, resources)
}

// ── GrantAccess – ResourceTypeRAMRole ────────────────────────────────────────

func TestGrantAccess_RAMRole_STSTrustPolicy_Success(t *testing.T) {
	mockClient := mocks.NewAliCloudRAMClient(t)
	p := newTestProvider()
	pc := testProviderConfig(ResourceTypeRAMRole)
	p.Clients[pc.URN] = mockClient

	resource := &domain.Resource{
		Type: ResourceTypeRAMRole,
		URN:  "acs:ram::5348956882036640:role/DevRole",
		Name: "DevRole",
	}
	grant := domain.Grant{
		AccountID:   "acs:ram::5348956882036640:user/test-bot-user-rba1",
		AccountType: AccountTypeRamUser,
		Role:        STSTrustPolicyRole,
		Resource:    resource,
	}

	mockClient.EXPECT().
		GrantRamRoleAccess(mock.Anything, *resource, grant.AccountID, STSTrustPolicyRole).
		Return(nil)

	err := p.GrantAccess(context.Background(), pc, grant)
	assert.NoError(t, err)
}

func TestGrantAccess_RAMRole_ClientError(t *testing.T) {
	mockClient := mocks.NewAliCloudRAMClient(t)
	p := newTestProvider()
	pc := testProviderConfig(ResourceTypeRAMRole)
	p.Clients[pc.URN] = mockClient

	resource := &domain.Resource{
		Type: ResourceTypeRAMRole,
		URN:  "acs:ram::5348956882036640:role/DevRole",
		Name: "DevRole",
	}
	grant := domain.Grant{
		AccountID:   "acs:ram::5348956882036640:user/test-bot-user-rba1",
		AccountType: AccountTypeRamUser,
		Role:        STSTrustPolicyRole,
		Resource:    resource,
	}

	mockClient.EXPECT().
		GrantRamRoleAccess(mock.Anything, *resource, grant.AccountID, STSTrustPolicyRole).
		Return(errors.New("update failed"))

	err := p.GrantAccess(context.Background(), pc, grant)
	assert.Error(t, err)
	assert.ErrorContains(t, err, ResourceTypeRAMRole)
}

// ── RevokeAccess – ResourceTypeRAMRole ───────────────────────────────────────

func TestRevokeAccess_RAMRole_STSTrustPolicy_Success(t *testing.T) {
	mockClient := mocks.NewAliCloudRAMClient(t)
	p := newTestProvider()
	pc := testProviderConfig(ResourceTypeRAMRole)
	p.Clients[pc.URN] = mockClient

	resource := &domain.Resource{
		Type: ResourceTypeRAMRole,
		URN:  "acs:ram::5348956882036640:role/DevRole",
		Name: "DevRole",
	}
	grant := domain.Grant{
		AccountID:   "acs:ram::5348956882036640:user/test-bot-user-rba1",
		AccountType: AccountTypeRamUser,
		Role:        STSTrustPolicyRole,
		Resource:    resource,
	}

	mockClient.EXPECT().
		RevokeRamRoleAccess(mock.Anything, *resource, grant.AccountID, STSTrustPolicyRole).
		Return(nil)

	err := p.RevokeAccess(context.Background(), pc, grant)
	assert.NoError(t, err)
}

func TestRevokeAccess_RAMRole_ClientError(t *testing.T) {
	mockClient := mocks.NewAliCloudRAMClient(t)
	p := newTestProvider()
	pc := testProviderConfig(ResourceTypeRAMRole)
	p.Clients[pc.URN] = mockClient

	resource := &domain.Resource{
		Type: ResourceTypeRAMRole,
		URN:  "acs:ram::5348956882036640:role/DevRole",
		Name: "DevRole",
	}
	grant := domain.Grant{
		AccountID:   "acs:ram::5348956882036640:user/test-bot-user-rba1",
		AccountType: AccountTypeRamUser,
		Role:        STSTrustPolicyRole,
		Resource:    resource,
	}

	mockClient.EXPECT().
		RevokeRamRoleAccess(mock.Anything, *resource, grant.AccountID, STSTrustPolicyRole).
		Return(errors.New("update failed"))

	err := p.RevokeAccess(context.Background(), pc, grant)
	assert.Error(t, err)
	assert.ErrorContains(t, err, ResourceTypeRAMRole)
}
