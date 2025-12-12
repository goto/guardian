package domain_test

import (
	"errors"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockEncryptor struct {
	mock.Mock
}

func (m *mockEncryptor) Encrypt(plainText string) (string, error) {
	args := m.Called(plainText)
	return args.String(0), args.Error(1)
}

type mockDecryptor struct {
	mock.Mock
}

func (m *mockDecryptor) Decrypt(encryptedText string) (string, error) {
	args := m.Called(encryptedText)
	return args.String(0), args.Error(1)
}

func TestCustomSteps_EncryptConfig(t *testing.T) {
	tests := []struct {
		name            string
		customSteps     *domain.CustomSteps
		mockSetup       func(*mockEncryptor)
		expectedConfig  interface{}
		expectedError   string
	}{
		{
			name: "successful encryption with map config",
			customSteps: &domain.CustomSteps{
				Type: "http",
				Config: map[string]interface{}{
					"url":    "https://api.example.com",
					"method": "POST",
				},
			},
			mockSetup: func(enc *mockEncryptor) {
				enc.On("Encrypt", `{"method":"POST","url":"https://api.example.com"}`).Return("encrypted_config", nil)
			},
			expectedConfig: "encrypted_config",
			expectedError:  "",
		},
		{
			name: "successful encryption with string config",
			customSteps: &domain.CustomSteps{
				Type:   "static",
				Config: "simple_string_config",
			},
			mockSetup: func(enc *mockEncryptor) {
				enc.On("Encrypt", `"simple_string_config"`).Return("encrypted_string", nil)
			},
			expectedConfig: "encrypted_string",
			expectedError:  "",
		},
		{
			name: "encryption failure",
			customSteps: &domain.CustomSteps{
				Type:   "http",
				Config: map[string]interface{}{"key": "value"},
			},
			mockSetup: func(enc *mockEncryptor) {
				enc.On("Encrypt", mock.Anything).Return("", errors.New("encryption failed"))
			},
			expectedConfig: map[string]interface{}{"key": "value"}, // Config remains unchanged
			expectedError:  "encryption failed",
		},
		{
			name: "nil config",
			customSteps: &domain.CustomSteps{
				Type:   "http",
				Config: nil,
			},
			mockSetup: func(enc *mockEncryptor) {
				enc.On("Encrypt", `null`).Return("encrypted_null", nil)
			},
			expectedConfig: "encrypted_null",
			expectedError:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := new(mockEncryptor)
			tt.mockSetup(enc)

			err := tt.customSteps.EncryptConfig(enc)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedConfig, tt.customSteps.Config)
			}

			enc.AssertExpectations(t)
		})
	}
}

func TestCustomSteps_DecryptConfig(t *testing.T) {
	tests := []struct {
		name            string
		customSteps     *domain.CustomSteps
		mockSetup       func(*mockDecryptor)
		expectedConfig  interface{}
		expectedError   string
	}{
		{
			name: "successful decryption to map",
			customSteps: &domain.CustomSteps{
				Type:   "http",
				Config: "encrypted_config",
			},
			mockSetup: func(dec *mockDecryptor) {
				dec.On("Decrypt", "encrypted_config").Return(`{"url":"https://api.example.com","method":"POST"}`, nil)
			},
			expectedConfig: map[string]interface{}{
				"url":    "https://api.example.com",
				"method": "POST",
			},
			expectedError: "",
		},
		{
			name: "successful decryption to string",
			customSteps: &domain.CustomSteps{
				Type:   "static",
				Config: "encrypted_string",
			},
			mockSetup: func(dec *mockDecryptor) {
				dec.On("Decrypt", "encrypted_string").Return(`"simple_string_config"`, nil)
			},
			expectedConfig: "simple_string_config",
			expectedError: "",
		},
		{
			name: "successful decryption to array",
			customSteps: &domain.CustomSteps{
				Type:   "http",
				Config: "encrypted_array",
			},
			mockSetup: func(dec *mockDecryptor) {
				dec.On("Decrypt", "encrypted_array").Return(`["item1","item2","item3"]`, nil)
			},
			expectedConfig: []interface{}{"item1", "item2", "item3"},
			expectedError:  "",
		},
		{
			name: "invalid config type - not string",
			customSteps: &domain.CustomSteps{
				Type:   "http",
				Config: map[string]interface{}{"already": "decrypted"},
			},
			mockSetup:      func(dec *mockDecryptor) {},
			expectedConfig: map[string]interface{}{"already": "decrypted"},
			expectedError:  "invalid config type: map[string]interface {}, expected string",
		},
		{
			name: "decryption failure",
			customSteps: &domain.CustomSteps{
				Type:   "http",
				Config: "encrypted_config",
			},
			mockSetup: func(dec *mockDecryptor) {
				dec.On("Decrypt", "encrypted_config").Return("", errors.New("decryption failed"))
			},
			expectedConfig: "encrypted_config",
			expectedError:  "decryption failed",
		},
		{
			name: "invalid JSON after decryption",
			customSteps: &domain.CustomSteps{
				Type:   "http",
				Config: "encrypted_config",
			},
			mockSetup: func(dec *mockDecryptor) {
				dec.On("Decrypt", "encrypted_config").Return("invalid json", nil)
			},
			expectedConfig: "encrypted_config",
			expectedError:  "failed to json.Unmarshal config",
		},
		{
			name: "nil decrypted to null",
			customSteps: &domain.CustomSteps{
				Type:   "http",
				Config: "encrypted_null",
			},
			mockSetup: func(dec *mockDecryptor) {
				dec.On("Decrypt", "encrypted_null").Return(`null`, nil)
			},
			expectedConfig: nil,
			expectedError:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := new(mockDecryptor)
			tt.mockSetup(dec)

			err := tt.customSteps.DecryptConfig(dec)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedConfig, tt.customSteps.Config)
			}

			dec.AssertExpectations(t)
		})
	}
}

func TestCustomSteps_EncryptDecryptRoundTrip(t *testing.T) {
	// Test that encrypt followed by decrypt returns the original value
	originalConfig := map[string]interface{}{
		"url":     "https://api.example.com",
		"method":  "POST",
		"headers": map[string]interface{}{
			"Content-Type": "application/json",
			"X-API-Key":    "secret-key",
		},
		"timeout": float64(30),
	}

	customSteps := &domain.CustomSteps{
		Type:   "http",
		Config: originalConfig,
	}

	enc := new(mockEncryptor)
	dec := new(mockDecryptor)

	// Setup encryption
	expectedJSON := `{"headers":{"Content-Type":"application/json","X-API-Key":"secret-key"},"method":"POST","timeout":30,"url":"https://api.example.com"}`
	enc.On("Encrypt", expectedJSON).Return("encrypted_data", nil)

	// Setup decryption
	dec.On("Decrypt", "encrypted_data").Return(expectedJSON, nil)

	// Encrypt
	err := customSteps.EncryptConfig(enc)
	assert.NoError(t, err)
	assert.Equal(t, "encrypted_data", customSteps.Config)

	// Decrypt
	err = customSteps.DecryptConfig(dec)
	assert.NoError(t, err)
	
	// Verify the decrypted config matches the original
	assert.Equal(t, originalConfig, customSteps.Config)

	enc.AssertExpectations(t)
	dec.AssertExpectations(t)
}