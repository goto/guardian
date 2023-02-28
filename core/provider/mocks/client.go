// Code generated by mockery v2.10.0. DO NOT EDIT.

package mocks

import (
	context "context"

	domain "github.com/goto/guardian/domain"
	mock "github.com/stretchr/testify/mock"
)

// Client is an autogenerated mock type for the Client type
type Client struct {
	mock.Mock
}

type Client_Expecter struct {
	mock *mock.Mock
}

func (_m *Client) EXPECT() *Client_Expecter {
	return &Client_Expecter{mock: &_m.Mock}
}

// CreateConfig provides a mock function with given fields: _a0
func (_m *Client) CreateConfig(_a0 *domain.ProviderConfig) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*domain.ProviderConfig) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Client_CreateConfig_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateConfig'
type Client_CreateConfig_Call struct {
	*mock.Call
}

// CreateConfig is a helper method to define mock.On call
//  - _a0 *domain.ProviderConfig
func (_e *Client_Expecter) CreateConfig(_a0 interface{}) *Client_CreateConfig_Call {
	return &Client_CreateConfig_Call{Call: _e.mock.On("CreateConfig", _a0)}
}

func (_c *Client_CreateConfig_Call) Run(run func(_a0 *domain.ProviderConfig)) *Client_CreateConfig_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*domain.ProviderConfig))
	})
	return _c
}

func (_c *Client_CreateConfig_Call) Return(_a0 error) *Client_CreateConfig_Call {
	_c.Call.Return(_a0)
	return _c
}

// GetAccountTypes provides a mock function with given fields:
func (_m *Client) GetAccountTypes() []string {
	ret := _m.Called()

	var r0 []string
	if rf, ok := ret.Get(0).(func() []string); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	return r0
}

// Client_GetAccountTypes_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAccountTypes'
type Client_GetAccountTypes_Call struct {
	*mock.Call
}

// GetAccountTypes is a helper method to define mock.On call
func (_e *Client_Expecter) GetAccountTypes() *Client_GetAccountTypes_Call {
	return &Client_GetAccountTypes_Call{Call: _e.mock.On("GetAccountTypes")}
}

func (_c *Client_GetAccountTypes_Call) Run(run func()) *Client_GetAccountTypes_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Client_GetAccountTypes_Call) Return(_a0 []string) *Client_GetAccountTypes_Call {
	_c.Call.Return(_a0)
	return _c
}

// GetPermissions provides a mock function with given fields: p, resourceType, role
func (_m *Client) GetPermissions(p *domain.ProviderConfig, resourceType string, role string) ([]interface{}, error) {
	ret := _m.Called(p, resourceType, role)

	var r0 []interface{}
	if rf, ok := ret.Get(0).(func(*domain.ProviderConfig, string, string) []interface{}); ok {
		r0 = rf(p, resourceType, role)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]interface{})
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*domain.ProviderConfig, string, string) error); ok {
		r1 = rf(p, resourceType, role)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Client_GetPermissions_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetPermissions'
type Client_GetPermissions_Call struct {
	*mock.Call
}

// GetPermissions is a helper method to define mock.On call
//  - p *domain.ProviderConfig
//  - resourceType string
//  - role string
func (_e *Client_Expecter) GetPermissions(p interface{}, resourceType interface{}, role interface{}) *Client_GetPermissions_Call {
	return &Client_GetPermissions_Call{Call: _e.mock.On("GetPermissions", p, resourceType, role)}
}

func (_c *Client_GetPermissions_Call) Run(run func(p *domain.ProviderConfig, resourceType string, role string)) *Client_GetPermissions_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*domain.ProviderConfig), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *Client_GetPermissions_Call) Return(_a0 []interface{}, _a1 error) *Client_GetPermissions_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

// GetResources provides a mock function with given fields: pc
func (_m *Client) GetResources(pc *domain.ProviderConfig) ([]*domain.Resource, error) {
	ret := _m.Called(pc)

	var r0 []*domain.Resource
	if rf, ok := ret.Get(0).(func(*domain.ProviderConfig) []*domain.Resource); ok {
		r0 = rf(pc)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*domain.Resource)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*domain.ProviderConfig) error); ok {
		r1 = rf(pc)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Client_GetResources_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetResources'
type Client_GetResources_Call struct {
	*mock.Call
}

// GetResources is a helper method to define mock.On call
//  - pc *domain.ProviderConfig
func (_e *Client_Expecter) GetResources(pc interface{}) *Client_GetResources_Call {
	return &Client_GetResources_Call{Call: _e.mock.On("GetResources", pc)}
}

func (_c *Client_GetResources_Call) Run(run func(pc *domain.ProviderConfig)) *Client_GetResources_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*domain.ProviderConfig))
	})
	return _c
}

func (_c *Client_GetResources_Call) Return(_a0 []*domain.Resource, _a1 error) *Client_GetResources_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

// GetRoles provides a mock function with given fields: pc, resourceType
func (_m *Client) GetRoles(pc *domain.ProviderConfig, resourceType string) ([]*domain.Role, error) {
	ret := _m.Called(pc, resourceType)

	var r0 []*domain.Role
	if rf, ok := ret.Get(0).(func(*domain.ProviderConfig, string) []*domain.Role); ok {
		r0 = rf(pc, resourceType)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*domain.Role)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*domain.ProviderConfig, string) error); ok {
		r1 = rf(pc, resourceType)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Client_GetRoles_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetRoles'
type Client_GetRoles_Call struct {
	*mock.Call
}

// GetRoles is a helper method to define mock.On call
//  - pc *domain.ProviderConfig
//  - resourceType string
func (_e *Client_Expecter) GetRoles(pc interface{}, resourceType interface{}) *Client_GetRoles_Call {
	return &Client_GetRoles_Call{Call: _e.mock.On("GetRoles", pc, resourceType)}
}

func (_c *Client_GetRoles_Call) Run(run func(pc *domain.ProviderConfig, resourceType string)) *Client_GetRoles_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*domain.ProviderConfig), args[1].(string))
	})
	return _c
}

func (_c *Client_GetRoles_Call) Return(_a0 []*domain.Role, _a1 error) *Client_GetRoles_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

// GetType provides a mock function with given fields:
func (_m *Client) GetType() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Client_GetType_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetType'
type Client_GetType_Call struct {
	*mock.Call
}

// GetType is a helper method to define mock.On call
func (_e *Client_Expecter) GetType() *Client_GetType_Call {
	return &Client_GetType_Call{Call: _e.mock.On("GetType")}
}

func (_c *Client_GetType_Call) Run(run func()) *Client_GetType_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Client_GetType_Call) Return(_a0 string) *Client_GetType_Call {
	_c.Call.Return(_a0)
	return _c
}

// GrantAccess provides a mock function with given fields: _a0, _a1
func (_m *Client) GrantAccess(_a0 *domain.ProviderConfig, _a1 domain.Grant) error {
	ret := _m.Called(_a0, _a1)

	var r0 error
	if rf, ok := ret.Get(0).(func(*domain.ProviderConfig, domain.Grant) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Client_GrantAccess_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GrantAccess'
type Client_GrantAccess_Call struct {
	*mock.Call
}

// GrantAccess is a helper method to define mock.On call
//  - _a0 *domain.ProviderConfig
//  - _a1 domain.Grant
func (_e *Client_Expecter) GrantAccess(_a0 interface{}, _a1 interface{}) *Client_GrantAccess_Call {
	return &Client_GrantAccess_Call{Call: _e.mock.On("GrantAccess", _a0, _a1)}
}

func (_c *Client_GrantAccess_Call) Run(run func(_a0 *domain.ProviderConfig, _a1 domain.Grant)) *Client_GrantAccess_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*domain.ProviderConfig), args[1].(domain.Grant))
	})
	return _c
}

func (_c *Client_GrantAccess_Call) Return(_a0 error) *Client_GrantAccess_Call {
	_c.Call.Return(_a0)
	return _c
}

// ListAccess provides a mock function with given fields: _a0, _a1, _a2
func (_m *Client) ListAccess(_a0 context.Context, _a1 domain.ProviderConfig, _a2 []*domain.Resource) (domain.MapResourceAccess, error) {
	ret := _m.Called(_a0, _a1, _a2)

	var r0 domain.MapResourceAccess
	if rf, ok := ret.Get(0).(func(context.Context, domain.ProviderConfig, []*domain.Resource) domain.MapResourceAccess); ok {
		r0 = rf(_a0, _a1, _a2)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(domain.MapResourceAccess)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, domain.ProviderConfig, []*domain.Resource) error); ok {
		r1 = rf(_a0, _a1, _a2)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Client_ListAccess_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListAccess'
type Client_ListAccess_Call struct {
	*mock.Call
}

// ListAccess is a helper method to define mock.On call
//  - _a0 context.Context
//  - _a1 domain.ProviderConfig
//  - _a2 []*domain.Resource
func (_e *Client_Expecter) ListAccess(_a0 interface{}, _a1 interface{}, _a2 interface{}) *Client_ListAccess_Call {
	return &Client_ListAccess_Call{Call: _e.mock.On("ListAccess", _a0, _a1, _a2)}
}

func (_c *Client_ListAccess_Call) Run(run func(_a0 context.Context, _a1 domain.ProviderConfig, _a2 []*domain.Resource)) *Client_ListAccess_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(domain.ProviderConfig), args[2].([]*domain.Resource))
	})
	return _c
}

func (_c *Client_ListAccess_Call) Return(_a0 domain.MapResourceAccess, _a1 error) *Client_ListAccess_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

// RevokeAccess provides a mock function with given fields: _a0, _a1
func (_m *Client) RevokeAccess(_a0 *domain.ProviderConfig, _a1 domain.Grant) error {
	ret := _m.Called(_a0, _a1)

	var r0 error
	if rf, ok := ret.Get(0).(func(*domain.ProviderConfig, domain.Grant) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Client_RevokeAccess_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RevokeAccess'
type Client_RevokeAccess_Call struct {
	*mock.Call
}

// RevokeAccess is a helper method to define mock.On call
//  - _a0 *domain.ProviderConfig
//  - _a1 domain.Grant
func (_e *Client_Expecter) RevokeAccess(_a0 interface{}, _a1 interface{}) *Client_RevokeAccess_Call {
	return &Client_RevokeAccess_Call{Call: _e.mock.On("RevokeAccess", _a0, _a1)}
}

func (_c *Client_RevokeAccess_Call) Run(run func(_a0 *domain.ProviderConfig, _a1 domain.Grant)) *Client_RevokeAccess_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*domain.ProviderConfig), args[1].(domain.Grant))
	})
	return _c
}

func (_c *Client_RevokeAccess_Call) Return(_a0 error) *Client_RevokeAccess_Call {
	_c.Call.Return(_a0)
	return _c
}
