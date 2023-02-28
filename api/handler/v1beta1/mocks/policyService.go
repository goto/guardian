// Code generated by mockery v2.10.0. DO NOT EDIT.

package mocks

import (
	context "context"

	domain "github.com/goto/guardian/domain"
	mock "github.com/stretchr/testify/mock"
)

// PolicyService is an autogenerated mock type for the policyService type
type PolicyService struct {
	mock.Mock
}

type PolicyService_Expecter struct {
	mock *mock.Mock
}

func (_m *PolicyService) EXPECT() *PolicyService_Expecter {
	return &PolicyService_Expecter{mock: &_m.Mock}
}

// Create provides a mock function with given fields: _a0, _a1
func (_m *PolicyService) Create(_a0 context.Context, _a1 *domain.Policy) error {
	ret := _m.Called(_a0, _a1)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *domain.Policy) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// PolicyService_Create_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Create'
type PolicyService_Create_Call struct {
	*mock.Call
}

// Create is a helper method to define mock.On call
//  - _a0 context.Context
//  - _a1 *domain.Policy
func (_e *PolicyService_Expecter) Create(_a0 interface{}, _a1 interface{}) *PolicyService_Create_Call {
	return &PolicyService_Create_Call{Call: _e.mock.On("Create", _a0, _a1)}
}

func (_c *PolicyService_Create_Call) Run(run func(_a0 context.Context, _a1 *domain.Policy)) *PolicyService_Create_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*domain.Policy))
	})
	return _c
}

func (_c *PolicyService_Create_Call) Return(_a0 error) *PolicyService_Create_Call {
	_c.Call.Return(_a0)
	return _c
}

// Find provides a mock function with given fields: _a0
func (_m *PolicyService) Find(_a0 context.Context) ([]*domain.Policy, error) {
	ret := _m.Called(_a0)

	var r0 []*domain.Policy
	if rf, ok := ret.Get(0).(func(context.Context) []*domain.Policy); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*domain.Policy)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PolicyService_Find_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Find'
type PolicyService_Find_Call struct {
	*mock.Call
}

// Find is a helper method to define mock.On call
//  - _a0 context.Context
func (_e *PolicyService_Expecter) Find(_a0 interface{}) *PolicyService_Find_Call {
	return &PolicyService_Find_Call{Call: _e.mock.On("Find", _a0)}
}

func (_c *PolicyService_Find_Call) Run(run func(_a0 context.Context)) *PolicyService_Find_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *PolicyService_Find_Call) Return(_a0 []*domain.Policy, _a1 error) *PolicyService_Find_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

// GetOne provides a mock function with given fields: ctx, id, version
func (_m *PolicyService) GetOne(ctx context.Context, id string, version uint) (*domain.Policy, error) {
	ret := _m.Called(ctx, id, version)

	var r0 *domain.Policy
	if rf, ok := ret.Get(0).(func(context.Context, string, uint) *domain.Policy); ok {
		r0 = rf(ctx, id, version)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*domain.Policy)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, uint) error); ok {
		r1 = rf(ctx, id, version)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PolicyService_GetOne_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetOne'
type PolicyService_GetOne_Call struct {
	*mock.Call
}

// GetOne is a helper method to define mock.On call
//  - ctx context.Context
//  - id string
//  - version uint
func (_e *PolicyService_Expecter) GetOne(ctx interface{}, id interface{}, version interface{}) *PolicyService_GetOne_Call {
	return &PolicyService_GetOne_Call{Call: _e.mock.On("GetOne", ctx, id, version)}
}

func (_c *PolicyService_GetOne_Call) Run(run func(ctx context.Context, id string, version uint)) *PolicyService_GetOne_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(uint))
	})
	return _c
}

func (_c *PolicyService_GetOne_Call) Return(_a0 *domain.Policy, _a1 error) *PolicyService_GetOne_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

// Update provides a mock function with given fields: _a0, _a1
func (_m *PolicyService) Update(_a0 context.Context, _a1 *domain.Policy) error {
	ret := _m.Called(_a0, _a1)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *domain.Policy) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// PolicyService_Update_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Update'
type PolicyService_Update_Call struct {
	*mock.Call
}

// Update is a helper method to define mock.On call
//  - _a0 context.Context
//  - _a1 *domain.Policy
func (_e *PolicyService_Expecter) Update(_a0 interface{}, _a1 interface{}) *PolicyService_Update_Call {
	return &PolicyService_Update_Call{Call: _e.mock.On("Update", _a0, _a1)}
}

func (_c *PolicyService_Update_Call) Run(run func(_a0 context.Context, _a1 *domain.Policy)) *PolicyService_Update_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*domain.Policy))
	})
	return _c
}

func (_c *PolicyService_Update_Call) Return(_a0 error) *PolicyService_Update_Call {
	_c.Call.Return(_a0)
	return _c
}
