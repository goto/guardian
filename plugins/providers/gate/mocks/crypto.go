// Code generated by mockery v2.33.0. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// Encryptor is an autogenerated mock type for the encryptor type
type Encryptor struct {
	mock.Mock
}

type Encryptor_Expecter struct {
	mock *mock.Mock
}

func (_m *Encryptor) EXPECT() *Encryptor_Expecter {
	return &Encryptor_Expecter{mock: &_m.Mock}
}

// Decrypt provides a mock function with given fields: _a0
func (_m *Encryptor) Decrypt(_a0 string) (string, error) {
	ret := _m.Called(_a0)

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (string, error)); ok {
		return rf(_a0)
	}
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Encryptor_Decrypt_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Decrypt'
type Encryptor_Decrypt_Call struct {
	*mock.Call
}

// Decrypt is a helper method to define mock.On call
//   - _a0 string
func (_e *Encryptor_Expecter) Decrypt(_a0 interface{}) *Encryptor_Decrypt_Call {
	return &Encryptor_Decrypt_Call{Call: _e.mock.On("Decrypt", _a0)}
}

func (_c *Encryptor_Decrypt_Call) Run(run func(_a0 string)) *Encryptor_Decrypt_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *Encryptor_Decrypt_Call) Return(_a0 string, _a1 error) *Encryptor_Decrypt_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Encryptor_Decrypt_Call) RunAndReturn(run func(string) (string, error)) *Encryptor_Decrypt_Call {
	_c.Call.Return(run)
	return _c
}

// Encrypt provides a mock function with given fields: _a0
func (_m *Encryptor) Encrypt(_a0 string) (string, error) {
	ret := _m.Called(_a0)

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (string, error)); ok {
		return rf(_a0)
	}
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Encryptor_Encrypt_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Encrypt'
type Encryptor_Encrypt_Call struct {
	*mock.Call
}

// Encrypt is a helper method to define mock.On call
//   - _a0 string
func (_e *Encryptor_Expecter) Encrypt(_a0 interface{}) *Encryptor_Encrypt_Call {
	return &Encryptor_Encrypt_Call{Call: _e.mock.On("Encrypt", _a0)}
}

func (_c *Encryptor_Encrypt_Call) Run(run func(_a0 string)) *Encryptor_Encrypt_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *Encryptor_Encrypt_Call) Return(_a0 string, _a1 error) *Encryptor_Encrypt_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Encryptor_Encrypt_Call) RunAndReturn(run func(string) (string, error)) *Encryptor_Encrypt_Call {
	_c.Call.Return(run)
	return _c
}

// NewEncryptor creates a new instance of Encryptor. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewEncryptor(t interface {
	mock.TestingT
	Cleanup(func())
}) *Encryptor {
	mock := &Encryptor{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
