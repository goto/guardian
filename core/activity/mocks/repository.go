// Code generated by mockery v2.10.0. DO NOT EDIT.

package mocks

import (
	context "context"

	domain "github.com/goto/guardian/domain"
	mock "github.com/stretchr/testify/mock"
)

// Repository is an autogenerated mock type for the repository type
type Repository struct {
	mock.Mock
}

type Repository_Expecter struct {
	mock *mock.Mock
}

func (_m *Repository) EXPECT() *Repository_Expecter {
	return &Repository_Expecter{mock: &_m.Mock}
}

// BulkUpsert provides a mock function with given fields: _a0, _a1
func (_m *Repository) BulkUpsert(_a0 context.Context, _a1 []*domain.Activity) error {
	ret := _m.Called(_a0, _a1)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, []*domain.Activity) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Repository_BulkUpsert_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'BulkUpsert'
type Repository_BulkUpsert_Call struct {
	*mock.Call
}

// BulkUpsert is a helper method to define mock.On call
//  - _a0 context.Context
//  - _a1 []*domain.Activity
func (_e *Repository_Expecter) BulkUpsert(_a0 interface{}, _a1 interface{}) *Repository_BulkUpsert_Call {
	return &Repository_BulkUpsert_Call{Call: _e.mock.On("BulkUpsert", _a0, _a1)}
}

func (_c *Repository_BulkUpsert_Call) Run(run func(_a0 context.Context, _a1 []*domain.Activity)) *Repository_BulkUpsert_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].([]*domain.Activity))
	})
	return _c
}

func (_c *Repository_BulkUpsert_Call) Return(_a0 error) *Repository_BulkUpsert_Call {
	_c.Call.Return(_a0)
	return _c
}

// Find provides a mock function with given fields: _a0, _a1
func (_m *Repository) Find(_a0 context.Context, _a1 domain.ListProviderActivitiesFilter) ([]*domain.Activity, error) {
	ret := _m.Called(_a0, _a1)

	var r0 []*domain.Activity
	if rf, ok := ret.Get(0).(func(context.Context, domain.ListProviderActivitiesFilter) []*domain.Activity); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*domain.Activity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, domain.ListProviderActivitiesFilter) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Repository_Find_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Find'
type Repository_Find_Call struct {
	*mock.Call
}

// Find is a helper method to define mock.On call
//  - _a0 context.Context
//  - _a1 domain.ListProviderActivitiesFilter
func (_e *Repository_Expecter) Find(_a0 interface{}, _a1 interface{}) *Repository_Find_Call {
	return &Repository_Find_Call{Call: _e.mock.On("Find", _a0, _a1)}
}

func (_c *Repository_Find_Call) Run(run func(_a0 context.Context, _a1 domain.ListProviderActivitiesFilter)) *Repository_Find_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(domain.ListProviderActivitiesFilter))
	})
	return _c
}

func (_c *Repository_Find_Call) Return(_a0 []*domain.Activity, _a1 error) *Repository_Find_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

// GetOne provides a mock function with given fields: _a0, _a1
func (_m *Repository) GetOne(_a0 context.Context, _a1 string) (*domain.Activity, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *domain.Activity
	if rf, ok := ret.Get(0).(func(context.Context, string) *domain.Activity); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*domain.Activity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Repository_GetOne_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetOne'
type Repository_GetOne_Call struct {
	*mock.Call
}

// GetOne is a helper method to define mock.On call
//  - _a0 context.Context
//  - _a1 string
func (_e *Repository_Expecter) GetOne(_a0 interface{}, _a1 interface{}) *Repository_GetOne_Call {
	return &Repository_GetOne_Call{Call: _e.mock.On("GetOne", _a0, _a1)}
}

func (_c *Repository_GetOne_Call) Run(run func(_a0 context.Context, _a1 string)) *Repository_GetOne_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *Repository_GetOne_Call) Return(_a0 *domain.Activity, _a1 error) *Repository_GetOne_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}
