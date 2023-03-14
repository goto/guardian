// Code generated by mockery v2.10.0. DO NOT EDIT.

package mocks

import (
	context "context"

	domain "github.com/goto/guardian/domain"

	mock "github.com/stretchr/testify/mock"
)

// ResourceService is an autogenerated mock type for the resourceService type
type ResourceService struct {
	mock.Mock
}

type ResourceService_Expecter struct {
	mock *mock.Mock
}

func (_m *ResourceService) EXPECT() *ResourceService_Expecter {
	return &ResourceService_Expecter{mock: &_m.Mock}
}

// Find provides a mock function with given fields: _a0, _a1
func (_m *ResourceService) Find(_a0 context.Context, _a1 domain.ListResourcesFilter) ([]*domain.Resource, error) {
	ret := _m.Called(_a0, _a1)

	var r0 []*domain.Resource
	if rf, ok := ret.Get(0).(func(context.Context, domain.ListResourcesFilter) []*domain.Resource); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*domain.Resource)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, domain.ListResourcesFilter) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ResourceService_Find_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Find'
type ResourceService_Find_Call struct {
	*mock.Call
}

// Find is a helper method to define mock.On call
//  - _a0 context.Context
//  - _a1 domain.ListResourcesFilter
func (_e *ResourceService_Expecter) Find(_a0 interface{}, _a1 interface{}) *ResourceService_Find_Call {
	return &ResourceService_Find_Call{Call: _e.mock.On("Find", _a0, _a1)}
}

func (_c *ResourceService_Find_Call) Run(run func(_a0 context.Context, _a1 domain.ListResourcesFilter)) *ResourceService_Find_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(domain.ListResourcesFilter))
	})
	return _c
}

func (_c *ResourceService_Find_Call) Return(_a0 []*domain.Resource, _a1 error) *ResourceService_Find_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}
