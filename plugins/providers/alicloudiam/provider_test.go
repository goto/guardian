package alicloudiam_test

import (
	"context"
	"errors"
	ram "github.com/alibabacloud-go/ram-20150501/v2/client"
	"github.com/bearaujus/bptr"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/mocks"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/plugins/providers/alicloudiam"
	alicloudiamMocks "github.com/goto/guardian/plugins/providers/alicloudiam/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestNewProvider(t *testing.T) {
	type args struct {
		typeName string
		crypto   domain.Crypto
		logger   log.Logger
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "success create a new provider",
			args: args{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotNil(t, alicloudiam.NewProvider(tt.args.typeName, tt.args.crypto, tt.args.logger))
		})
	}
}

func TestProvider_GetType(t *testing.T) {
	type args struct {
		typeName string
		crypto   domain.Crypto
		logger   log.Logger
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "success get type",
			args: args{
				typeName: "alicloud_iam",
			},
			want: "alicloud_iam",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := alicloudiam.NewProvider(tt.args.typeName, tt.args.crypto, tt.args.logger)
			assert.Equalf(t, tt.want, p.GetType(), "GetType()")
		})
	}
}

func TestProvider_CreateConfig(t *testing.T) {
	crypto := new(mocks.Crypto)
	client := new(alicloudiamMocks.AliCloudIamClient)
	type args struct {
		typeName string
		crypto   domain.Crypto
		logger   log.Logger
		pc       *domain.ProviderConfig
	}
	tests := []struct {
		name       string
		args       args
		mock       func(p *alicloudiam.Provider)
		assertFunc func(p *alicloudiam.Provider)
		wantErr    bool
	}{
		{
			name: "error when parse & validate config",
			args: args{
				crypto: crypto,
				pc: &domain.ProviderConfig{
					URN:         "test-urn",
					Credentials: nil,
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
			},
			mock:       nil,
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error when get all policies by type",
			args: args{
				crypto: crypto,
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return(nil, errors.New("test")).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return(nil, errors.New("test")).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error policy type is invalid",
			args: args{
				crypto: crypto,
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        "invalid type",
									Permissions: []interface{}{"test-system-policy-permission"},
								},
							},
						},
					},
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error policy permission is not exist for policy type system",
			args: args{
				crypto: crypto,
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"invalid-system-policy-permission"},
								},
							},
						},
					},
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error policy permission is not exist for policy type custom",
			args: args{
				crypto: crypto,
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"invalid-custom-policy-permission"},
								},
							},
						},
					},
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "success",
			args: args{
				crypto: crypto,
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
			},
			assertFunc: func(p *alicloudiam.Provider) {
				assert.Equal(t, 1, len(p.Clients))
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := alicloudiam.NewProvider(tt.args.typeName, tt.args.crypto, tt.args.logger)
			if tt.mock != nil {
				tt.mock(p)
			}
			err := p.CreateConfig(tt.args.pc)
			if tt.assertFunc != nil {
				tt.assertFunc(p)
			}
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProvider_GetResources(t *testing.T) {
	crypto := new(mocks.Crypto)
	type args struct {
		typeName string
		crypto   domain.Crypto
		logger   log.Logger
		ctx      context.Context
		pc       *domain.ProviderConfig
	}
	tests := []struct {
		name       string
		args       args
		mock       func(p *alicloudiam.Provider)
		assertFunc func(p *alicloudiam.Provider, r []*domain.Resource)
		wantErr    bool
	}{
		{
			name: "error invalid credentials type",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: &domain.ProviderConfig{
					URN:         "test-urn",
					Type:        "alicloud_iam",
					Credentials: "",
					Resources:   []*domain.ResourceConfig{{Type: alicloudiam.ResourceTypeAccount}},
				},
			},
			mock:       nil,
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error invalid resource type",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: &domain.ProviderConfig{
					URN:  "test-urn",
					Type: "alicloud_iam",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{{Type: "invalid-resource-type"}},
				},
			},
			mock:       nil,
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "success",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: &domain.ProviderConfig{
					URN:  "test-urn",
					Type: "alicloud_iam",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{{Type: alicloudiam.ResourceTypeAccount}},
				},
			},
			mock: nil,
			assertFunc: func(p *alicloudiam.Provider, r []*domain.Resource) {
				assert.ElementsMatch(t, []*domain.Resource{{
					ProviderType: "alicloud_iam",
					ProviderURN:  "test-urn",
					Type:         alicloudiam.ResourceTypeAccount,
					URN:          "test-resource-name",
					Name:         "test-resource-name - AliCloud IAM",
					GlobalURN:    "urn:alicloudiam:test-urn:account:test-resource-name",
				}}, r)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := alicloudiam.NewProvider(tt.args.typeName, tt.args.crypto, tt.args.logger)
			if tt.mock != nil {
				tt.mock(p)
			}
			r, err := p.GetResources(tt.args.ctx, tt.args.pc)
			if tt.assertFunc != nil {
				tt.assertFunc(p, r)
			}
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProvider_GrantAccess(t *testing.T) {
	crypto := new(mocks.Crypto)
	client := new(alicloudiamMocks.AliCloudIamClient)
	type args struct {
		typeName string
		crypto   domain.Crypto
		logger   log.Logger
		ctx      context.Context
		pc       *domain.ProviderConfig
		g        domain.Grant
	}
	tests := []struct {
		name       string
		args       args
		mock       func(p *alicloudiam.Provider)
		assertFunc func(p *alicloudiam.Provider)
		wantErr    bool
	}{
		{
			name: "error empty grant role name",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error grant role is not found at resource",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
				g: domain.Grant{
					Role: "invalid-grant-role-id",
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error invalid grant resource type",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
				g: domain.Grant{
					Role:     "test-system-policy",
					Resource: &domain.Resource{Type: "test-invalid-grant-resource-type"},
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error invalid grant account type",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
				g: domain.Grant{
					Role:        "test-system-policy",
					Resource:    &domain.Resource{Type: alicloudiam.ResourceTypeAccount},
					AccountType: "test-invalid-account-type",
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error grant access to user invalid ali account id",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
				g: domain.Grant{
					Role:        "test-system-policy",
					Resource:    &domain.Resource{Type: alicloudiam.ResourceTypeAccount},
					AccountType: alicloudiam.AccountTypeRamUser,
					AccountID:   "test-invalid-account-id",
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error grant access to user",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
				g: domain.Grant{
					Role:        "test-system-policy",
					Resource:    &domain.Resource{Type: alicloudiam.ResourceTypeAccount},
					AccountType: alicloudiam.AccountTypeRamUser,
					AccountID:   "test-user@12345679.onaliyun.com",
					Permissions: []string{"test-system-policy-permission"},
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
				client.EXPECT().GrantAccess(mock.Anything, "test-system-policy-permission", alicloudiam.PolicyTypeSystem, "test-user").Return(errors.New("test")).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error grant access to role",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
				g: domain.Grant{
					Role:        "test-system-policy",
					Resource:    &domain.Resource{Type: alicloudiam.ResourceTypeAccount},
					AccountType: alicloudiam.AccountTypeRamRole,
					AccountID:   "test-role",
					Permissions: []string{"test-system-policy-permission"},
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
				client.EXPECT().GrantAccessToRole(mock.Anything, "test-system-policy-permission", alicloudiam.PolicyTypeSystem, "test-role").Return(errors.New("test")).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "success grant access to user",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
				g: domain.Grant{
					Role:        "test-system-policy",
					Resource:    &domain.Resource{Type: alicloudiam.ResourceTypeAccount},
					AccountType: alicloudiam.AccountTypeRamUser,
					AccountID:   "test-user@12345679.onaliyun.com",
					Permissions: []string{"test-system-policy-permission"},
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
				client.EXPECT().GrantAccess(mock.Anything, "test-system-policy-permission", alicloudiam.PolicyTypeSystem, "test-user").Return(nil).Once()
			},
			assertFunc: nil,
			wantErr:    false,
		},
		{
			name: "success grant access to role",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
				g: domain.Grant{
					Role:        "test-system-policy",
					Resource:    &domain.Resource{Type: alicloudiam.ResourceTypeAccount},
					AccountType: alicloudiam.AccountTypeRamRole,
					AccountID:   "test-role",
					Permissions: []string{"test-system-policy-permission"},
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
				client.EXPECT().GrantAccessToRole(mock.Anything, "test-system-policy-permission", alicloudiam.PolicyTypeSystem, "test-role").Return(nil).Once()
			},
			assertFunc: nil,
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := alicloudiam.NewProvider(tt.args.typeName, tt.args.crypto, tt.args.logger)
			if tt.mock != nil {
				tt.mock(p)
			}
			err := p.CreateConfig(tt.args.pc)
			if err != nil {
				assert.FailNow(t, "fail to initialize provider config", err.Error())
			}
			err = p.GrantAccess(tt.args.ctx, tt.args.pc, tt.args.g)
			if tt.assertFunc != nil {
				tt.assertFunc(p)
			}
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProvider_RevokeAccess(t *testing.T) {
	crypto := new(mocks.Crypto)
	client := new(alicloudiamMocks.AliCloudIamClient)
	type args struct {
		typeName string
		crypto   domain.Crypto
		logger   log.Logger
		ctx      context.Context
		pc       *domain.ProviderConfig
		g        domain.Grant
	}
	tests := []struct {
		name       string
		args       args
		mock       func(p *alicloudiam.Provider)
		assertFunc func(p *alicloudiam.Provider)
		wantErr    bool
	}{
		{
			name: "error empty grant role name",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error grant role is not found at resource",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
				g: domain.Grant{
					Role: "invalid-grant-role-id",
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error invalid grant resource type",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
				g: domain.Grant{
					Role:     "test-system-policy",
					Resource: &domain.Resource{Type: "test-invalid-grant-resource-type"},
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error invalid grant account type",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
				g: domain.Grant{
					Role:        "test-system-policy",
					Resource:    &domain.Resource{Type: alicloudiam.ResourceTypeAccount},
					AccountType: "test-invalid-account-type",
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error revoke access from user invalid ali account id",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
				g: domain.Grant{
					Role:        "test-system-policy",
					Resource:    &domain.Resource{Type: alicloudiam.ResourceTypeAccount},
					AccountType: alicloudiam.AccountTypeRamUser,
					AccountID:   "test-invalid-account-id",
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error revoke access from user",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
				g: domain.Grant{
					Role:        "test-system-policy",
					Resource:    &domain.Resource{Type: alicloudiam.ResourceTypeAccount},
					AccountType: alicloudiam.AccountTypeRamUser,
					AccountID:   "test-user@12345679.onaliyun.com",
					Permissions: []string{"test-system-policy-permission"},
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
				client.EXPECT().RevokeAccess(mock.Anything, "test-system-policy-permission", alicloudiam.PolicyTypeSystem, "test-user").Return(errors.New("test")).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error revoke access from role",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
				g: domain.Grant{
					Role:        "test-system-policy",
					Resource:    &domain.Resource{Type: alicloudiam.ResourceTypeAccount},
					AccountType: alicloudiam.AccountTypeRamRole,
					AccountID:   "test-role",
					Permissions: []string{"test-system-policy-permission"},
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
				client.EXPECT().RevokeAccessFromRole(mock.Anything, "test-system-policy-permission", alicloudiam.PolicyTypeSystem, "test-role").Return(errors.New("test")).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "success revoke access from user",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
				g: domain.Grant{
					Role:        "test-system-policy",
					Resource:    &domain.Resource{Type: alicloudiam.ResourceTypeAccount},
					AccountType: alicloudiam.AccountTypeRamUser,
					AccountID:   "test-user@12345679.onaliyun.com",
					Permissions: []string{"test-system-policy-permission"},
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
				client.EXPECT().RevokeAccess(mock.Anything, "test-system-policy-permission", alicloudiam.PolicyTypeSystem, "test-user").Return(nil).Once()
			},
			assertFunc: nil,
			wantErr:    false,
		},
		{
			name: "success revoke access from role",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
				g: domain.Grant{
					Role:        "test-system-policy",
					Resource:    &domain.Resource{Type: alicloudiam.ResourceTypeAccount},
					AccountType: alicloudiam.AccountTypeRamRole,
					AccountID:   "test-role",
					Permissions: []string{"test-system-policy-permission"},
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
				client.EXPECT().RevokeAccessFromRole(mock.Anything, "test-system-policy-permission", alicloudiam.PolicyTypeSystem, "test-role").Return(nil).Once()
			},
			assertFunc: nil,
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := alicloudiam.NewProvider(tt.args.typeName, tt.args.crypto, tt.args.logger)
			if tt.mock != nil {
				tt.mock(p)
			}
			err := p.CreateConfig(tt.args.pc)
			if err != nil {
				assert.FailNow(t, "fail to initialize provider config", err.Error())
			}
			err = p.RevokeAccess(tt.args.ctx, tt.args.pc, tt.args.g)
			if tt.assertFunc != nil {
				tt.assertFunc(p)
			}
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProvider_GetRoles(t *testing.T) {
	crypto := new(mocks.Crypto)
	type args struct {
		typeName     string
		crypto       domain.Crypto
		logger       log.Logger
		pc           *domain.ProviderConfig
		resourceType string
	}
	tests := []struct {
		name       string
		args       args
		mock       func(p *alicloudiam.Provider)
		assertFunc func(r []*domain.Role, p *alicloudiam.Provider)
		wantErr    bool
	}{
		{
			name: "success get roles",
			args: args{
				crypto: crypto,
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
				resourceType: alicloudiam.ResourceTypeAccount,
			},
			mock: nil,
			assertFunc: func(r []*domain.Role, p *alicloudiam.Provider) {
				assert.ElementsMatch(t, []*domain.Role{
					{
						ID:          "test-system-policy",
						Name:        "test-system-policy",
						Type:        alicloudiam.PolicyTypeSystem,
						Permissions: []interface{}{"test-system-policy-permission"},
					},
					{
						ID:          "test-custom-policy",
						Name:        "test-custom-policy",
						Type:        alicloudiam.PolicyTypeCustom,
						Permissions: []interface{}{"test-custom-policy-permission"},
					},
				}, r)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := alicloudiam.NewProvider(tt.args.typeName, tt.args.crypto, tt.args.logger)
			if tt.mock != nil {
				tt.mock(p)
			}
			r, err := p.GetRoles(tt.args.pc, tt.args.resourceType)
			if tt.assertFunc != nil {
				tt.assertFunc(r, p)
			}
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProvider_GetPermissions(t *testing.T) {
	crypto := new(mocks.Crypto)
	type args struct {
		typeName     string
		crypto       domain.Crypto
		logger       log.Logger
		pc           *domain.ProviderConfig
		resourceType string
		role         string
	}
	tests := []struct {
		name       string
		args       args
		mock       func(p *alicloudiam.Provider)
		assertFunc func(r []interface{}, p *alicloudiam.Provider)
		wantErr    bool
	}{
		{
			name: "success get permissions",
			args: args{
				crypto: crypto,
				pc: &domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
				resourceType: alicloudiam.ResourceTypeAccount,
				role:         "test-system-policy",
			},
			mock: nil,
			assertFunc: func(r []interface{}, p *alicloudiam.Provider) {
				assert.ElementsMatch(t, []interface{}{"test-system-policy-permission"}, r)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := alicloudiam.NewProvider(tt.args.typeName, tt.args.crypto, tt.args.logger)
			if tt.mock != nil {
				tt.mock(p)
			}
			r, err := p.GetPermissions(tt.args.pc, tt.args.resourceType, tt.args.role)
			if tt.assertFunc != nil {
				tt.assertFunc(r, p)
			}
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProvider_GetAccountTypes(t *testing.T) {
	crypto := new(mocks.Crypto)
	type args struct {
		typeName string
		crypto   domain.Crypto
		logger   log.Logger
	}
	tests := []struct {
		name       string
		args       args
		mock       func(p *alicloudiam.Provider)
		assertFunc func(r []string, p *alicloudiam.Provider)
	}{
		{
			name: "success get account types",
			args: args{
				crypto: crypto,
			},
			mock: nil,
			assertFunc: func(r []string, p *alicloudiam.Provider) {
				assert.ElementsMatch(t, []string{alicloudiam.AccountTypeRamUser, alicloudiam.AccountTypeRamRole}, r)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := alicloudiam.NewProvider(tt.args.typeName, tt.args.crypto, tt.args.logger)
			if tt.mock != nil {
				tt.mock(p)
			}
			r := p.GetAccountTypes()
			if tt.assertFunc != nil {
				tt.assertFunc(r, p)
			}
		})
	}
}

func TestProvider_ListAccess(t *testing.T) {
	crypto := new(mocks.Crypto)
	client := new(alicloudiamMocks.AliCloudIamClient)
	type args struct {
		typeName string
		crypto   domain.Crypto
		logger   log.Logger
		ctx      context.Context
		pc       domain.ProviderConfig
		r        []*domain.Resource
	}
	tests := []struct {
		name       string
		args       args
		mock       func(p *alicloudiam.Provider)
		assertFunc func(a domain.MapResourceAccess, p *alicloudiam.Provider)
		wantErr    bool
	}{
		{
			name: "success get list access",
			args: args{
				crypto: crypto,
				ctx:    context.TODO(),
				pc: domain.ProviderConfig{
					URN: "test-urn",
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:          "test-system-policy",
									Name:        "test-system-policy",
									Type:        alicloudiam.PolicyTypeSystem,
									Permissions: []interface{}{"test-system-policy-permission"},
								},
								{
									ID:          "test-custom-policy",
									Name:        "test-custom-policy",
									Type:        alicloudiam.PolicyTypeCustom,
									Permissions: []interface{}{"test-custom-policy-permission"},
								},
							},
						},
					},
				},
			},
			mock: func(p *alicloudiam.Provider) {
				p.Clients["test-urn"] = client
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeSystem, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-system-policy-permission")}}, nil).Once()
				client.EXPECT().GetAllPoliciesByType(mock.Anything, alicloudiam.PolicyTypeCustom, mock.Anything).Return([]*ram.ListPoliciesResponseBodyPoliciesPolicy{
					{PolicyName: bptr.FromString("test-custom-policy-permission")}}, nil).Once()
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
				client.EXPECT().ListAccess(mock.Anything, mock.Anything, mock.Anything).Return(domain.MapResourceAccess{}, nil).Once()
			},
			assertFunc: nil,
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := alicloudiam.NewProvider(tt.args.typeName, tt.args.crypto, tt.args.logger)
			if tt.mock != nil {
				tt.mock(p)
			}
			err := p.CreateConfig(&tt.args.pc)
			if err != nil {
				assert.FailNow(t, "fail to initialize provider config", err.Error())
			}
			a, err := p.ListAccess(tt.args.ctx, tt.args.pc, tt.args.r)
			if tt.assertFunc != nil {
				tt.assertFunc(a, p)
			}
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
