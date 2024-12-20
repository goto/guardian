package alicloud_ram_test

import (
	"errors"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/mocks"
	"github.com/goto/guardian/plugins/providers/alicloud_ram"
	"github.com/stretchr/testify/assert"
)

const (
	testMainAccountID            = "5123xxxxxxxxxx"
	testAccessKeyID              = "test-access-key-id"
	testAccessKeySecret          = "test-access-key-secret"
	testEncryptedAccessKeyID     = "test-encrypted-access-key-id"
	testEncryptedAccessKeySecret = "test-encrypted-access-key-secret"

	// no worries this is base64 from random string
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
		field      *alicloud_ram.Credentials
		args       args
		mock       func(field *alicloud_ram.Credentials)
		assertFunc func(field *alicloud_ram.Credentials)
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
			field: &alicloud_ram.Credentials{
				MainAccountID:   testMainAccountID,
				AccessKeyID:     testAccessKeyID,
				AccessKeySecret: testAccessKeySecret,
			},
			args: args{encryptor: encryptor},
			mock: func(c *alicloud_ram.Credentials) {
				encryptor.On("Encrypt", c.AccessKeyID).Return("", errors.New("test")).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error when encrypting access key secret",
			field: &alicloud_ram.Credentials{
				MainAccountID:   testMainAccountID,
				AccessKeyID:     testAccessKeyID,
				AccessKeySecret: testAccessKeySecret,
			},
			args: args{encryptor: encryptor},
			mock: func(c *alicloud_ram.Credentials) {
				encryptor.On("Encrypt", c.AccessKeyID).Return(testEncryptedAccessKeyID, nil).Once()
				encryptor.On("Encrypt", c.AccessKeySecret).Return("", errors.New("test")).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "success encrypting credentials",
			field: &alicloud_ram.Credentials{
				MainAccountID:   testMainAccountID,
				AccessKeyID:     testAccessKeyID,
				AccessKeySecret: testAccessKeySecret,
			},
			args: args{encryptor: encryptor},
			mock: func(c *alicloud_ram.Credentials) {
				encryptor.On("Encrypt", c.AccessKeyID).Return(testEncryptedAccessKeyID, nil).Once()
				encryptor.On("Encrypt", c.AccessKeySecret).Return(testEncryptedAccessKeySecret, nil).Once()
			},
			assertFunc: func(field *alicloud_ram.Credentials) {
				assert.Equal(t, testEncryptedAccessKeyID, field.AccessKeyID)
				assert.Equal(t, testEncryptedAccessKeySecret, field.AccessKeySecret)
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
		field      *alicloud_ram.Credentials
		args       args
		mock       func(field *alicloud_ram.Credentials)
		assertFunc func(field *alicloud_ram.Credentials)
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
			field: &alicloud_ram.Credentials{

				AccessKeyID:     testEncryptedAccessKeyID,
				AccessKeySecret: testEncryptedAccessKeySecret,
			},
			args: args{decryptor: decryptor},
			mock: func(c *alicloud_ram.Credentials) {
				decryptor.On("Decrypt", c.AccessKeyID).Return("", errors.New("test")).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "error when decrypting access key secret",
			field: &alicloud_ram.Credentials{
				AccessKeyID:     testEncryptedAccessKeyID,
				AccessKeySecret: testEncryptedAccessKeySecret,
			},
			args: args{decryptor: decryptor},
			mock: func(c *alicloud_ram.Credentials) {
				decryptor.On("Decrypt", c.AccessKeyID).Return(testAccessKeyID, nil).Once()
				decryptor.On("Decrypt", c.AccessKeySecret).Return("", errors.New("test")).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "success decrypting credentials",
			field: &alicloud_ram.Credentials{
				AccessKeyID:     testEncryptedAccessKeyID,
				AccessKeySecret: testEncryptedAccessKeySecret,
			},
			args: args{decryptor: decryptor},
			mock: func(c *alicloud_ram.Credentials) {
				decryptor.On("Decrypt", c.AccessKeyID).Return(testAccessKeyID, nil).Once()
				decryptor.On("Decrypt", c.AccessKeySecret).Return(testAccessKeySecret, nil).Once()
			},
			assertFunc: func(field *alicloud_ram.Credentials) {
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
			assert.NotNil(t, alicloud_ram.NewConfig(tt.args.pc, tt.args.crypto))
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
		mock       func(c *alicloud_ram.Config)
		assertFunc func(c *alicloud_ram.Config)
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
				pc: &domain.ProviderConfig{Credentials: &alicloud_ram.Credentials{
					MainAccountID:   testMainAccountID,
					AccessKeyID:     testEncodedAccessKeyID,
					AccessKeySecret: testEncodedAccessKeySecret,
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
					Credentials: &alicloud_ram.Credentials{
						MainAccountID:   testMainAccountID,
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
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
					Credentials: &alicloud_ram.Credentials{
						MainAccountID:   testMainAccountID,
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloud_ram.ResourceTypeAccount,
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
					Credentials: &alicloud_ram.Credentials{
						MainAccountID:   testMainAccountID,
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloud_ram.ResourceTypeAccount,
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
			name: "error contain duplicate resource type",
			field: field{
				pc: &domain.ProviderConfig{
					Credentials: &alicloud_ram.Credentials{
						MainAccountID:   testMainAccountID,
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloud_ram.ResourceTypeAccount,
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
							Type: alicloud_ram.ResourceTypeAccount,
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
					Credentials: &alicloud_ram.Credentials{
						MainAccountID:   testMainAccountID,
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloud_ram.ResourceTypeAccount,
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
					Credentials: &alicloud_ram.Credentials{
						MainAccountID:   testMainAccountID,
						AccessKeyID:     "dGVzdC1hY2Nlc3Mta2V5LWlk",
						AccessKeySecret: testEncodedAccessKeySecret,
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloud_ram.ResourceTypeAccount,
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
			assertFunc: func(c *alicloud_ram.Config) {
				// try to re-call it
				assert.NoError(t, c.ParseAndValidate())
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := alicloud_ram.NewConfig(tt.field.pc, tt.field.crypto)
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
		mock       func(c *alicloud_ram.Config)
		assertFunc func(c *alicloud_ram.Config)
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
					Credentials: &alicloud_ram.Credentials{
						MainAccountID:   testMainAccountID,
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloud_ram.ResourceTypeAccount,
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
			mock: func(c *alicloud_ram.Config) {
				crypto.On("Encrypt", testAccessKeyID).Return("", errors.New("test")).Once()
			},
			assertFunc: nil,
			wantErr:    true,
		},
		{
			name: "success encrypt config credentials",
			field: field{
				pc: &domain.ProviderConfig{
					Credentials: &alicloud_ram.Credentials{
						MainAccountID:   testMainAccountID,
						AccessKeyID:     testEncodedAccessKeyID,
						AccessKeySecret: testEncodedAccessKeySecret,
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: alicloud_ram.ResourceTypeAccount,
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
			mock: func(c *alicloud_ram.Config) {
				crypto.On("Encrypt", testAccessKeyID).Return(testEncryptedAccessKeyID, nil).Once()
				crypto.On("Encrypt", testAccessKeySecret).Return(testEncryptedAccessKeySecret, nil).Once()
			},
			assertFunc: func(c *alicloud_ram.Config) {
				credentials := c.ProviderConfig.Credentials.(*alicloud_ram.Credentials)
				assert.Equal(t, testEncryptedAccessKeyID, credentials.AccessKeyID)
				assert.Equal(t, testEncryptedAccessKeySecret, credentials.AccessKeySecret)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := alicloud_ram.NewConfig(tt.field.pc, tt.field.crypto)
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
