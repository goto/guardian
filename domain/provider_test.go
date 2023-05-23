package domain

import (
	"testing"

	"github.com/goto/guardian/domain/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestEncryptCredentials(t *testing.T) {
	t.Run("should encrypt credentials", func(t *testing.T) {
		mockEncryptor := new(mocks.Encryptor)
		mockEncryptor.EXPECT().Encrypt(`{"foo":"bar"}`).Return("encrypted", nil).Times(1)

		pc := &ProviderConfig{
			Credentials: map[string]interface{}{"foo": "bar"},
		}
		err := pc.EncryptCredentials(mockEncryptor)

		assert.NoError(t, err)
		assert.Equal(t, "encrypted", pc.Credentials)
	})

	t.Run("should return nil if credentials is nil", func(t *testing.T) {
		pc := &ProviderConfig{}
		err := pc.EncryptCredentials(nil)

		assert.NoError(t, err)
		assert.Nil(t, pc.Credentials)
	})

	t.Run("should return error if credentials are not serializable", func(t *testing.T) {
		pc := &ProviderConfig{
			Credentials: make(chan int),
		}
		err := pc.EncryptCredentials(nil)

		assert.Error(t, err)
	})

	t.Run("should return error if encryptor fails", func(t *testing.T) {
		mockEncryptor := new(mocks.Encryptor)
		mockEncryptor.EXPECT().Encrypt(mock.AnythingOfType("string")).Return("", assert.AnError).Times(1)

		creds := map[string]interface{}{"foo": "bar"}
		pc := &ProviderConfig{
			Credentials: creds,
		}
		err := pc.EncryptCredentials(mockEncryptor)

		assert.Error(t, err)
		assert.Equal(t, creds, pc.Credentials)
	})
}

func TestDecryptCredentials(t *testing.T) {
	t.Run("should decrypt credentials", func(t *testing.T) {
		mockDecryptor := new(mocks.Decryptor)
		mockDecryptor.EXPECT().Decrypt("encrypted").Return(`{"foo":"bar"}`, nil).Times(1)

		pc := &ProviderConfig{
			Credentials: "encrypted",
		}
		err := pc.DecryptCredentials(mockDecryptor)

		assert.NoError(t, err)
		assert.Equal(t, map[string]interface{}{"foo": "bar"}, pc.Credentials)
	})

	t.Run("should return nil if credentials is nil", func(t *testing.T) {
		pc := &ProviderConfig{}
		err := pc.DecryptCredentials(nil)

		assert.NoError(t, err)
		assert.Nil(t, pc.Credentials)
	})

	t.Run("should return error if credentials is not a string", func(t *testing.T) {
		pc := &ProviderConfig{
			Credentials: 1,
		}
		err := pc.DecryptCredentials(nil)

		assert.Error(t, err)
	})

	t.Run("should return error if decryptor fails", func(t *testing.T) {
		mockDecryptor := new(mocks.Decryptor)
		mockDecryptor.EXPECT().Decrypt(mock.AnythingOfType("string")).Return("", assert.AnError).Times(1)

		pc := &ProviderConfig{
			Credentials: "encrypted",
		}
		err := pc.DecryptCredentials(mockDecryptor)

		assert.Error(t, err)
		assert.Equal(t, "encrypted", pc.Credentials)
	})

	t.Run("should return error if credentials are not deserializable", func(t *testing.T) {
		mockDecryptor := new(mocks.Decryptor)
		mockDecryptor.EXPECT().Decrypt(mock.AnythingOfType("string")).Return(`invalid json`, nil).Times(1)

		pc := &ProviderConfig{
			Credentials: "encrypted",
		}
		err := pc.DecryptCredentials(mockDecryptor)

		assert.Error(t, err)
	})
}
