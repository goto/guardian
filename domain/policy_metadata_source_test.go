package domain_test

import (
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/mocks"
	"github.com/stretchr/testify/assert"
)

func TestAppealMetadataSource_EncryptConfig(t *testing.T) {
	t.Run("should encrypt config", func(t *testing.T) {
		mockEncryptor := new(mocks.Crypto)
		mockEncryptor.EXPECT().Encrypt(`{"key":"value"}`).Return("encrypted", nil)
		defer mockEncryptor.AssertExpectations(t)

		ms := &domain.AppealMetadataSource{
			Config: map[string]interface{}{
				"key": "value",
			},
		}
		err := ms.EncryptConfig(mockEncryptor)

		assert.NoError(t, err)
		assert.Equal(t, "encrypted", ms.Config)
	})

	t.Run("should return error if marshalling fails", func(t *testing.T) {
		ms := &domain.AppealMetadataSource{
			Config: make(chan int),
		}
		err := ms.EncryptConfig(nil)

		assert.Error(t, err)
	})

	t.Run("should return error if encryption fails", func(t *testing.T) {
		mockEncryptor := new(mocks.Crypto)
		mockEncryptor.EXPECT().Encrypt(`{"key":"value"}`).Return("", assert.AnError)
		defer mockEncryptor.AssertExpectations(t)

		ms := &domain.AppealMetadataSource{
			Config: map[string]interface{}{
				"key": "value",
			},
		}
		err := ms.EncryptConfig(mockEncryptor)

		assert.Error(t, err)
	})
}

func TestAppealMetadataSource_DecryptConfig(t *testing.T) {
	t.Run("should decrypt config", func(t *testing.T) {
		mockDecryptor := new(mocks.Crypto)
		mockDecryptor.EXPECT().Decrypt("encrypted").Return(`{"key":"value"}`, nil)
		defer mockDecryptor.AssertExpectations(t)

		ms := &domain.AppealMetadataSource{
			Config: "encrypted",
		}
		err := ms.DecryptConfig(mockDecryptor)

		assert.NoError(t, err)
		assert.Equal(t, map[string]interface{}{"key": "value"}, ms.Config)
	})

	t.Run("should return error if config is not a string", func(t *testing.T) {
		ms := &domain.AppealMetadataSource{
			Config: 123,
		}
		err := ms.DecryptConfig(nil)

		assert.Error(t, err)
	})

	t.Run("should return error if decryption fails", func(t *testing.T) {
		mockDecryptor := new(mocks.Crypto)
		mockDecryptor.EXPECT().Decrypt("encrypted").Return("", assert.AnError)
		defer mockDecryptor.AssertExpectations(t)

		ms := &domain.AppealMetadataSource{
			Config: "encrypted",
		}
		err := ms.DecryptConfig(mockDecryptor)

		assert.Error(t, err)
	})

	t.Run("should return error if unmarshalling fails", func(t *testing.T) {
		mockDecryptor := new(mocks.Crypto)
		mockDecryptor.EXPECT().Decrypt("encrypted").Return("invalid-json", nil)
		defer mockDecryptor.AssertExpectations(t)

		ms := &domain.AppealMetadataSource{
			Config: "encrypted",
		}
		err := ms.DecryptConfig(mockDecryptor)

		assert.Error(t, err)
	})
}

func TestAppealMetadataSource_EvaluateValue(t *testing.T) {
	testCases := []struct {
		name          string
		value         interface{}
		params        map[string]interface{}
		expectedValue interface{}
	}{
		{
			name:          "string value",
			value:         "test",
			expectedValue: "test",
		},
		{
			name:          "int value",
			value:         10,
			expectedValue: 10,
		},
		{
			name:  "string value with params",
			value: "$appeal.foo",
			params: map[string]interface{}{
				"appeal": map[string]interface{}{
					"foo": "bar",
				},
			},
			expectedValue: "bar",
		},
		{
			name:  "string value with nested params",
			value: "$appeal.foo.bar",
			params: map[string]interface{}{
				"appeal": map[string]interface{}{
					"foo": map[string]interface{}{
						"bar": "baz",
					},
				},
			},
			expectedValue: "baz",
		},
		{
			name: "complex",
			value: map[string]interface{}{
				"policy":       `$appeal.policy_id + "@" + string($appeal.policy_version)`,
				"user_details": `$response.status_code == 200 ? $response.body.user[0] : nil`,
				"string_list": []string{
					"$appeal.details.list[0]",
					"$appeal.details.list[1]",
					"$appeal.details.list[2]",
				},
			},
			params: map[string]interface{}{
				"appeal": map[string]interface{}{
					"id":             "123",
					"policy_id":      "test-policy",
					"policy_version": 1,
					"details": map[string]interface{}{
						"list": []string{"a", "b", "c"},
					},
				},
				"response": map[string]interface{}{
					"status_code": 200,
					"body": map[string]interface{}{
						"user": []map[string]interface{}{
							{
								"id":    "123",
								"email": "user@example.com",
							},
						},
					},
				},
			},
			expectedValue: map[string]interface{}{
				"policy": "test-policy@1",
				"user_details": map[string]interface{}{
					"id":    "123",
					"email": "user@example.com",
				},
				"string_list": []interface{}{"a", "b", "c"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ms := &domain.AppealMetadataSource{
				Value: tc.value,
			}

			result, err := ms.EvaluateValue(tc.params)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedValue, result)
		})
	}
}
