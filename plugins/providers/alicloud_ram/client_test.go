package alicloud_ram_test

import (
	"context"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/plugins/providers/alicloud_ram"
	"github.com/stretchr/testify/assert"
)

func TestNewAliCloudRAMClient(t *testing.T) {
	type args struct {
		accessKeyID     string
		accessKeySecret string
		ramRole         string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "error creating AliCloud RAM client with role - invalid role arn",
			args: args{
				accessKeyID:     testAccessKeyID,
				accessKeySecret: testAccessKeySecret,
				ramRole:         "invalid-role-arn",
			},
			wantErr: true,
		},
		{
			name: "error creating AliCloud RAM client with role - unsupported service type",
			args: args{
				accessKeyID:     testAccessKeyID,
				accessKeySecret: testAccessKeySecret,
				ramRole:         "acs:unsupported-service-type::500xxxxxxxx:role/role-name",
			},
			wantErr: true,
		},
		{
			name: "error creating AliCloud RAM client with role - invalid resource",
			args: args{
				accessKeyID:     testAccessKeyID,
				accessKeySecret: testAccessKeySecret,
				ramRole:         "acs:ram::500xxxxxxxx:invalid-resource",
			},
			wantErr: true,
		},
		{
			name: "error creating AliCloud RAM client with role - unsupported resource type",
			args: args{
				accessKeyID:     testAccessKeyID,
				accessKeySecret: testAccessKeySecret,
				ramRole:         "acs:ram::500xxxxxxxx:unsupported-resource-type/role-name",
			},
			wantErr: true,
		},
		{
			name: "error creating AliCloud RAM client with role - empty role name or resource name",
			args: args{
				accessKeyID:     testAccessKeyID,
				accessKeySecret: testAccessKeySecret,
				ramRole:         "acs:ram::500xxxxxxxx:role/",
			},
			wantErr: true,
		},
		{
			name: "success creating AliCloud RAM client with role",
			args: args{
				accessKeyID:     testAccessKeyID,
				accessKeySecret: testAccessKeySecret,
				ramRole:         "acs:ram::500xxxxxxxx:role/role-name",
			},
			wantErr: false,
		},
		{
			name: "success creating AliCloud RAM client",
			args: args{
				accessKeyID:     testAccessKeyID,
				accessKeySecret: testAccessKeySecret,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := alicloud_ram.NewAliCloudRAMClient(tt.args.accessKeyID, tt.args.accessKeySecret, tt.args.ramRole)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NotNil(t, client)
				assert.NoError(t, err)
			}
		})
	}
}

func Test_aliCloudRAMClient_GrantAccess(t *testing.T) {
	type args struct {
		accessKeyID     string
		accessKeySecret string
		roleToAssume    string
		ctx             context.Context
		policyName      string
		policyType      string
		username        string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "error when granting access to user",
			args: args{
				accessKeyID:     testAccessKeyID,
				accessKeySecret: testAccessKeySecret,
				ctx:             context.TODO(),
				policyName:      "test-policy-name",
				policyType:      alicloud_ram.PolicyTypeSystem,
				username:        "test-user",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := alicloud_ram.NewAliCloudRAMClient(tt.args.accessKeyID, tt.args.accessKeySecret, tt.args.roleToAssume)
			if err != nil {
				assert.FailNow(t, err.Error())
			}
			err = client.GrantAccess(tt.args.ctx, tt.args.policyName, tt.args.policyType, tt.args.username)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NotNil(t, client)
				assert.NoError(t, err)
			}
		})
	}
}

func Test_aliCloudRAMClient_RevokeAccess(t *testing.T) {
	type args struct {
		accessKeyID     string
		accessKeySecret string
		roleToAssume    string
		ctx             context.Context
		policyName      string
		policyType      string
		username        string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "error when revoking access to user",
			args: args{
				accessKeyID:     testAccessKeyID,
				accessKeySecret: testAccessKeySecret,
				ctx:             context.TODO(),
				policyName:      "test-policy-name",
				policyType:      alicloud_ram.PolicyTypeSystem,
				username:        "test-user",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := alicloud_ram.NewAliCloudRAMClient(tt.args.accessKeyID, tt.args.accessKeySecret, tt.args.roleToAssume)
			if err != nil {
				assert.FailNow(t, err.Error())
			}
			err = client.RevokeAccess(tt.args.ctx, tt.args.policyName, tt.args.policyType, tt.args.username)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NotNil(t, client)
				assert.NoError(t, err)
			}
		})
	}
}

func Test_aliCloudRAMClient_GrantAccessToRole(t *testing.T) {
	type args struct {
		accessKeyID     string
		accessKeySecret string
		roleToAssume    string
		ctx             context.Context
		policyName      string
		policyType      string
		roleName        string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "error when granting access to role",
			args: args{
				accessKeyID:     testAccessKeyID,
				accessKeySecret: testAccessKeySecret,
				ctx:             context.TODO(),
				policyName:      "test-policy-name",
				policyType:      alicloud_ram.PolicyTypeSystem,
				roleName:        "test-role",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := alicloud_ram.NewAliCloudRAMClient(tt.args.accessKeyID, tt.args.accessKeySecret, tt.args.roleToAssume)
			if err != nil {
				assert.FailNow(t, err.Error())
			}
			err = client.GrantAccessToRole(tt.args.ctx, tt.args.policyName, tt.args.policyType, tt.args.roleName)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NotNil(t, client)
				assert.NoError(t, err)
			}
		})
	}
}

func Test_aliCloudRAMClient_RevokeAccessFromRole(t *testing.T) {
	type args struct {
		accessKeyID     string
		accessKeySecret string
		roleToAssume    string
		ctx             context.Context
		policyName      string
		policyType      string
		roleName        string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "error when revoking access to role",
			args: args{
				accessKeyID:     testAccessKeyID,
				accessKeySecret: testAccessKeySecret,
				ctx:             context.TODO(),
				policyName:      "test-policy-name",
				policyType:      alicloud_ram.PolicyTypeSystem,
				roleName:        "test-role",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := alicloud_ram.NewAliCloudRAMClient(tt.args.accessKeyID, tt.args.accessKeySecret, tt.args.roleToAssume)
			if err != nil {
				assert.FailNow(t, err.Error())
			}
			err = client.RevokeAccessFromRole(tt.args.ctx, tt.args.policyName, tt.args.policyType, tt.args.roleName)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NotNil(t, client)
				assert.NoError(t, err)
			}
		})
	}
}

func Test_aliCloudRAMClient_ListAccess(t *testing.T) {
	type args struct {
		accessKeyID     string
		accessKeySecret string
		roleToAssume    string
		ctx             context.Context
		pc              domain.ProviderConfig
		r               []*domain.Resource
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "error not implemented when listing access",
			args: args{
				accessKeyID:     testAccessKeyID,
				accessKeySecret: testAccessKeySecret,
				ctx:             context.TODO(),
				pc: domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloud_ram.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloud_ram.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := alicloud_ram.NewAliCloudRAMClient(tt.args.accessKeyID, tt.args.accessKeySecret, tt.args.roleToAssume)
			if err != nil {
				assert.FailNow(t, err.Error())
			}
			aes, err := client.ListAccess(tt.args.ctx, tt.args.pc, tt.args.r)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, aes)
			} else {
				assert.NotNil(t, client)
				assert.NoError(t, err)
			}
		})
	}
}

func Test_aliCloudRAMClient_GetAllPoliciesByType(t *testing.T) {
	type args struct {
		accessKeyID     string
		accessKeySecret string
		roleToAssume    string
		ctx             context.Context
		policyType      string
		maxItems        int32
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "error when get all policies by type",
			args: args{
				accessKeyID:     testAccessKeyID,
				accessKeySecret: testAccessKeySecret,
				ctx:             context.TODO(),
				policyType:      alicloud_ram.PolicyTypeSystem,
				maxItems:        1000,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := alicloud_ram.NewAliCloudRAMClient(tt.args.accessKeyID, tt.args.accessKeySecret, tt.args.roleToAssume)
			if err != nil {
				assert.FailNow(t, err.Error())
			}
			aes, err := client.GetAllPoliciesByType(tt.args.ctx, tt.args.policyType, tt.args.maxItems)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, aes)
			} else {
				assert.NotNil(t, client)
				assert.NoError(t, err)
			}
		})
	}
}
