// Code generated by mockery v2.20.0. DO NOT EDIT.

package mocks

import (
	context "context"

	domain "github.com/goto/guardian/domain"
	gcloudiam "github.com/goto/guardian/plugins/providers/gcloudiam"

	mock "github.com/stretchr/testify/mock"
)

// GcloudIamClient is an autogenerated mock type for the GcloudIamClient type
type GcloudIamClient struct {
	mock.Mock
}

type GcloudIamClient_Expecter struct {
	mock *mock.Mock
}

func (_m *GcloudIamClient) EXPECT() *GcloudIamClient_Expecter {
	return &GcloudIamClient_Expecter{mock: &_m.Mock}
}

// GetRoles provides a mock function with given fields:
func (_m *GcloudIamClient) GetRoles() ([]*gcloudiam.Role, error) {
	ret := _m.Called()

	var r0 []*gcloudiam.Role
	var r1 error
	if rf, ok := ret.Get(0).(func() ([]*gcloudiam.Role, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() []*gcloudiam.Role); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*gcloudiam.Role)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GcloudIamClient_GetRoles_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetRoles'
type GcloudIamClient_GetRoles_Call struct {
	*mock.Call
}

// GetRoles is a helper method to define mock.On call
func (_e *GcloudIamClient_Expecter) GetRoles() *GcloudIamClient_GetRoles_Call {
	return &GcloudIamClient_GetRoles_Call{Call: _e.mock.On("GetRoles")}
}

func (_c *GcloudIamClient_GetRoles_Call) Run(run func()) *GcloudIamClient_GetRoles_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *GcloudIamClient_GetRoles_Call) Return(_a0 []*gcloudiam.Role, _a1 error) *GcloudIamClient_GetRoles_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *GcloudIamClient_GetRoles_Call) RunAndReturn(run func() ([]*gcloudiam.Role, error)) *GcloudIamClient_GetRoles_Call {
	_c.Call.Return(run)
	return _c
}

// GrantAccess provides a mock function with given fields: accountType, accountID, role
func (_m *GcloudIamClient) GrantAccess(accountType string, accountID string, role string) error {
	ret := _m.Called(accountType, accountID, role)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string, string) error); ok {
		r0 = rf(accountType, accountID, role)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GcloudIamClient_GrantAccess_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GrantAccess'
type GcloudIamClient_GrantAccess_Call struct {
	*mock.Call
}

// GrantAccess is a helper method to define mock.On call
//   - accountType string
//   - accountID string
//   - role string
func (_e *GcloudIamClient_Expecter) GrantAccess(accountType interface{}, accountID interface{}, role interface{}) *GcloudIamClient_GrantAccess_Call {
	return &GcloudIamClient_GrantAccess_Call{Call: _e.mock.On("GrantAccess", accountType, accountID, role)}
}

func (_c *GcloudIamClient_GrantAccess_Call) Run(run func(accountType string, accountID string, role string)) *GcloudIamClient_GrantAccess_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *GcloudIamClient_GrantAccess_Call) Return(_a0 error) *GcloudIamClient_GrantAccess_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *GcloudIamClient_GrantAccess_Call) RunAndReturn(run func(string, string, string) error) *GcloudIamClient_GrantAccess_Call {
	_c.Call.Return(run)
	return _c
}

// ListAccess provides a mock function with given fields: ctx, resources
func (_m *GcloudIamClient) ListAccess(ctx context.Context, resources []*domain.Resource) (domain.MapResourceAccess, error) {
	ret := _m.Called(ctx, resources)

	var r0 domain.MapResourceAccess
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, []*domain.Resource) (domain.MapResourceAccess, error)); ok {
		return rf(ctx, resources)
	}
	if rf, ok := ret.Get(0).(func(context.Context, []*domain.Resource) domain.MapResourceAccess); ok {
		r0 = rf(ctx, resources)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(domain.MapResourceAccess)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, []*domain.Resource) error); ok {
		r1 = rf(ctx, resources)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GcloudIamClient_ListAccess_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListAccess'
type GcloudIamClient_ListAccess_Call struct {
	*mock.Call
}

// ListAccess is a helper method to define mock.On call
//   - ctx context.Context
//   - resources []*domain.Resource
func (_e *GcloudIamClient_Expecter) ListAccess(ctx interface{}, resources interface{}) *GcloudIamClient_ListAccess_Call {
	return &GcloudIamClient_ListAccess_Call{Call: _e.mock.On("ListAccess", ctx, resources)}
}

func (_c *GcloudIamClient_ListAccess_Call) Run(run func(ctx context.Context, resources []*domain.Resource)) *GcloudIamClient_ListAccess_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].([]*domain.Resource))
	})
	return _c
}

func (_c *GcloudIamClient_ListAccess_Call) Return(_a0 domain.MapResourceAccess, _a1 error) *GcloudIamClient_ListAccess_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *GcloudIamClient_ListAccess_Call) RunAndReturn(run func(context.Context, []*domain.Resource) (domain.MapResourceAccess, error)) *GcloudIamClient_ListAccess_Call {
	_c.Call.Return(run)
	return _c
}

// RevokeAccess provides a mock function with given fields: accountType, accountID, role
func (_m *GcloudIamClient) RevokeAccess(accountType string, accountID string, role string) error {
	ret := _m.Called(accountType, accountID, role)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string, string) error); ok {
		r0 = rf(accountType, accountID, role)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GcloudIamClient_RevokeAccess_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RevokeAccess'
type GcloudIamClient_RevokeAccess_Call struct {
	*mock.Call
}

// RevokeAccess is a helper method to define mock.On call
//   - accountType string
//   - accountID string
//   - role string
func (_e *GcloudIamClient_Expecter) RevokeAccess(accountType interface{}, accountID interface{}, role interface{}) *GcloudIamClient_RevokeAccess_Call {
	return &GcloudIamClient_RevokeAccess_Call{Call: _e.mock.On("RevokeAccess", accountType, accountID, role)}
}

func (_c *GcloudIamClient_RevokeAccess_Call) Run(run func(accountType string, accountID string, role string)) *GcloudIamClient_RevokeAccess_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *GcloudIamClient_RevokeAccess_Call) Return(_a0 error) *GcloudIamClient_RevokeAccess_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *GcloudIamClient_RevokeAccess_Call) RunAndReturn(run func(string, string, string) error) *GcloudIamClient_RevokeAccess_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewGcloudIamClient interface {
	mock.TestingT
	Cleanup(func())
}

// NewGcloudIamClient creates a new instance of GcloudIamClient. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewGcloudIamClient(t mockConstructorTestingTNewGcloudIamClient) *GcloudIamClient {
	mock := &GcloudIamClient{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
