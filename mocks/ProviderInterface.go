// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import (
	domain "github.com/odpf/guardian/domain"
	mock "github.com/stretchr/testify/mock"
)

// ProviderInterface is an autogenerated mock type for the ProviderInterface type
type ProviderInterface struct {
	mock.Mock
}

// CreateConfig provides a mock function with given fields: _a0
func (_m *ProviderInterface) CreateConfig(_a0 *domain.ProviderConfig) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*domain.ProviderConfig) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetType provides a mock function with given fields:
func (_m *ProviderInterface) GetType() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}
