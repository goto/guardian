package alicloudiam_test

import (
	"errors"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/mocks"
	"github.com/goto/guardian/plugins/providers/alicloudiam"
	"github.com/stretchr/testify/assert"
)

const (
	testAccessKeyID            = "test-access-key-id"
	testAccessKeySecret        = "test-access-key-secret"
	testEncodedAccessKeyID     = "dGVzdC1hY2Nlc3Mta2V5LWlk"
	testEncodedAccessKeySecret = "dGVzdC1hY2Nlc3Mta2V5LXNlY3JldA=="
)

func TestCredentials_Encrypt(t *testing.T) {
	encryptor := new(mocks.Encryptor)
	type args struct {
		encryptor domain.Encryptor
	}
	tests := []struct {
		name       string
		field      *alicloudiam.Credentials
		args       args
		mock       func(field *alicloudiam.Credentials)
		assertFunc func(field *alicloudiam.Credentials)
		wantErr    bool
	}{
		{
			name:       "error nil credentials",
			field:      nil,
			args:       args{encryptor: encryptor},
			mock:       nil,
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error when encrypting access key id",
			field: &alicloudiam.Credentials{
				AccessKeyID:     testAccessKeyID,
				AccessKeySecret: testAccessKeySecret,
				ResourceName:    "test-resource-name",
			},
			args: args{encryptor: encryptor},
			mock: func(c *alicloudiam.Credentials) {
				encryptor.On("Encrypt", c.AccessKeyID).Return("", errors.New("test")).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error when encrypting access key secret",
			field: &alicloudiam.Credentials{
				AccessKeyID:     testAccessKeyID,
				AccessKeySecret: testAccessKeySecret,
				ResourceName:    "test-resource-name",
			},
			args: args{encryptor: encryptor},
			mock: func(c *alicloudiam.Credentials) {
				encryptor.On("Encrypt", c.AccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				encryptor.On("Encrypt", c.AccessKeySecret).Return("", errors.New("test")).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "success encrypting credentials",
			field: &alicloudiam.Credentials{
				AccessKeyID:     testAccessKeyID,
				AccessKeySecret: testAccessKeySecret,
				ResourceName:    "test-resource-name",
			},
			args: args{encryptor: encryptor},
			mock: func(c *alicloudiam.Credentials) {
				encryptor.On("Encrypt", c.AccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				encryptor.On("Encrypt", c.AccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
			},
			assertFunc: func(field *alicloudiam.Credentials) {
				assert.Equal(t, "test-encrypted-access-key-id", field.AccessKeyID)
				assert.Equal(t, "test-encrypted-access-key-secret", field.AccessKeySecret)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.mock != nil {
				tt.mock(tt.field)
			}
			err := tt.field.Encrypt(tt.args.encryptor)
			if tt.assertFunc != nil {
				tt.assertFunc(tt.field)
			}
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCredentials_Decrypt(t *testing.T) {
	decryptor := new(mocks.Decryptor)
	type args struct {
		decryptor domain.Decryptor
	}
	tests := []struct {
		name       string
		field      *alicloudiam.Credentials
		args       args
		mock       func(field *alicloudiam.Credentials)
		assertFunc func(field *alicloudiam.Credentials)
		wantErr    bool
	}{
		{
			name:       "error nil credentials",
			field:      nil,
			args:       args{decryptor: decryptor},
			mock:       nil,
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error when decrypting access key id",
			field: &alicloudiam.Credentials{
				AccessKeyID:     "test-encrypted-access-key-id",
				AccessKeySecret: "test-encrypted-access-key-secret",
				ResourceName:    "test-resource-name",
			},
			args: args{decryptor: decryptor},
			mock: func(c *alicloudiam.Credentials) {
				decryptor.On("Decrypt", c.AccessKeyID).Return("", errors.New("test")).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error when decrypting access key secret",
			field: &alicloudiam.Credentials{
				AccessKeyID:     "test-encrypted-access-key-id",
				AccessKeySecret: "test-encrypted-access-key-secret",
				ResourceName:    "test-resource-name",
			},
			args: args{decryptor: decryptor},
			mock: func(c *alicloudiam.Credentials) {
				decryptor.On("Decrypt", c.AccessKeyID).Return(testAccessKeyID, nil).Once()
				decryptor.On("Decrypt", c.AccessKeySecret).Return("", errors.New("test")).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "success decrypting credentials",
			field: &alicloudiam.Credentials{
				AccessKeyID:     "test-encrypted-access-key-id",
				AccessKeySecret: "test-encrypted-access-key-secret",
				ResourceName:    "test-resource-name",
			},
			args: args{decryptor: decryptor},
			mock: func(c *alicloudiam.Credentials) {
				decryptor.On("Decrypt", c.AccessKeyID).Return(testAccessKeyID, nil).Once()
				decryptor.On("Decrypt", c.AccessKeySecret).Return(testAccessKeySecret, nil).Once()
			},
			assertFunc: func(field *alicloudiam.Credentials) {
				assert.Equal(t, testAccessKeyID, field.AccessKeyID)
				assert.Equal(t, testAccessKeySecret, field.AccessKeySecret)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.mock != nil {
				tt.mock(tt.field)
			}
			err := tt.field.Decrypt(tt.args.decryptor)
			if tt.assertFunc != nil {
				tt.assertFunc(tt.field)
			}
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewConfig(t *testing.T) {
	type args struct {
		pc     *domain.ProviderConfig
		crypto domain.Crypto
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "success create a new config",
			args: args{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotNil(t, alicloudiam.NewConfig(tt.args.pc, tt.args.crypto))
		})
	}
}

func TestConfig_ParseAndValidate(t *testing.T) {
	type field struct {
		pc     *domain.ProviderConfig
		crypto domain.Crypto
	}
	tests := []struct {
		name       string
		field      field
		mock       func(c *alicloudiam.Config)
		assertFunc func(c *alicloudiam.Config)
		wantErr    bool
	}{
		{
			name: "error when decode credentials",
			field: field{
				pc: &domain.ProviderConfig{Credentials: ""},
			},
			mock:       nil,
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error when decode credentials",
			field: field{
				pc: &domain.ProviderConfig{Credentials: nil},
			},
			mock:       nil,
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error empty resource",
			field: field{
				pc: &domain.ProviderConfig{Credentials: &alicloudiam.Credentials{
					AccessKeyID:     testEncodedAccessKeyID,
					AccessKeySecret: testEncodedAccessKeySecret,
					ResourceName:    "test-resource-name",
				}},
			},
			mock:       nil,
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error invalid resource type",
			field: field{
				pc: &domain.ProviderConfig{
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: "invalid-resource-type",
						},
					},
				},
			},
			mock:       nil,
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error empty resource role",
			field: field{
				pc: &domain.ProviderConfig{
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
						},
					},
				},
			},
			mock:       nil,
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error empty resource role permission",
			field: field{
				pc: &domain.ProviderConfig{
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
									ID:          "OSSReadAndOSSImportRead",
									Name:        "OSSReadAndOSSImportRead",
									Permissions: nil,
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
			name: "error contain empty resource role permission value",
			field: field{
				pc: &domain.ProviderConfig{
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
									ID:   "OSSReadAndOSSImportRead",
									Name: "OSSReadAndOSSImportRead",
									Permissions: []interface{}{
										"",
										"AliyunOSSImportReadOnlyAccess",
									},
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
			name: "error contain duplicate resource type",
			field: field{
				pc: &domain.ProviderConfig{
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
									ID:   "OSSReadAndOSSImportRead",
									Name: "OSSReadAndOSSImportRead",
									Permissions: []interface{}{
										"AliyunOSSReadOnlyAccess",
										"AliyunOSSImportReadOnlyAccess",
									},
								},
							},
						},
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:   "OSSReadAndOSSImportRead",
									Name: "OSSReadAndOSSImportRead",
									Permissions: []interface{}{
										"AliyunOSSReadOnlyAccess",
										"AliyunOSSImportReadOnlyAccess",
									},
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
			name: "error contain duplicate resource role id",
			field: field{
				pc: &domain.ProviderConfig{
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
									ID:   "OSSReadAndOSSImportRead",
									Name: "OSSReadAndOSSImportRead",
									Permissions: []interface{}{
										"AliyunOSSReadOnlyAccess",
										"AliyunOSSImportReadOnlyAccess",
									},
								},
								{
									ID:   "OSSReadAndOSSImportRead",
									Name: "OSSReadAndOSSImportRead",
									Permissions: []interface{}{
										"AliyunOSSReadOnlyAccess",
										"AliyunOSSImportReadOnlyAccess",
									},
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
			name: "success parse and validate",
			field: field{
				pc: &domain.ProviderConfig{
					Credentials: &alicloudiam.Credentials{
						AccessKeyID:     "dGVzdC1hY2Nlc3Mta2V5LWlk",
						AccessKeySecret: testEncodedAccessKeySecret,
						ResourceName:    "test-resource-name",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloudiam.ResourceTypeAccount,
							Roles: []*domain.Role{
								{
									ID:   "OSSReadAndOSSImportRead",
									Name: "OSSReadAndOSSImportRead",
									Permissions: []interface{}{
										"AliyunOSSReadOnlyAccess",
										"AliyunOSSImportReadOnlyAccess",
									},
								},
							},
						},
					},
				},
			},
			mock: nil,
			assertFunc: func(c *alicloudiam.Config) {
				// try to re-call it
				assert.NoError(t, c.ParseAndValidate())
				// check auto set policy type
				assert.Equal(t, c.ProviderConfig.Resources[0].Roles[0].Type, alicloudiam.PolicyTypeSystem)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := alicloudiam.NewConfig(tt.field.pc, tt.field.crypto)
			if tt.mock != nil {
				tt.mock(c)
			}
			err := c.ParseAndValidate()
			if tt.assertFunc != nil {
				tt.assertFunc(c)
			}
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfig_EncryptCredentials(t *testing.T) {
	crypto := new(mocks.Crypto)
	type field struct {
		pc     *domain.ProviderConfig
		crypto domain.Crypto
	}
	tests := []struct {
		name       string
		field      field
		mock       func(c *alicloudiam.Config)
		assertFunc func(c *alicloudiam.Config)
		wantErr    bool
	}{
		{
			name:       "error fail parse and validate config",
			field:      field{pc: &domain.ProviderConfig{Credentials: ""}},
			mock:       nil,
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error fail to encrypt config credentials",
			field: field{
				pc: &domain.ProviderConfig{
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
									ID:   "OSSReadAndOSSImportRead",
									Name: "OSSReadAndOSSImportRead",
									Permissions: []interface{}{
										"AliyunOSSReadOnlyAccess",
										"AliyunOSSImportReadOnlyAccess",
									},
								},
							},
						},
					},
				},
				crypto: crypto,
			},
			mock: func(c *alicloudiam.Config) {
				crypto.On("Encrypt", testAccessKeyID).Return("", errors.New("test")).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "success encrypt config credentials",
			field: field{
				pc: &domain.ProviderConfig{
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
									ID:   "OSSReadAndOSSImportRead",
									Name: "OSSReadAndOSSImportRead",
									Permissions: []interface{}{
										"AliyunOSSReadOnlyAccess",
										"AliyunOSSImportReadOnlyAccess",
									},
								},
							},
						},
					},
				},
				crypto: crypto,
			},
			mock: func(c *alicloudiam.Config) {
				crypto.On("Encrypt", testAccessKeyID).Return("test-encrypted-access-key-id", nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return("test-encrypted-access-key-secret", nil).Once()
			},
			assertFunc: func(c *alicloudiam.Config) {
				credentials := c.ProviderConfig.Credentials.(*alicloudiam.Credentials)
				assert.Equal(t, "test-encrypted-access-key-id", credentials.AccessKeyID)
				assert.Equal(t, "test-encrypted-access-key-secret", credentials.AccessKeySecret)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := alicloudiam.NewConfig(tt.field.pc, tt.field.crypto)
			if tt.mock != nil {
				tt.mock(c)
			}
			err := c.EncryptCredentials()
			if tt.assertFunc != nil {
				tt.assertFunc(c)
			}
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
