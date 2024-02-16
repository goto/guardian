// Code generated by mockery v2.20.0. DO NOT EDIT.

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

// BatchDelete provides a mock function with given fields: _a0, _a1
func (_m *Repository) BatchDelete(_a0 context.Context, _a1 []string) error {
	ret := _m.Called(_a0, _a1)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, []string) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Repository_BatchDelete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'BatchDelete'
type Repository_BatchDelete_Call struct {
	*mock.Call
}

// BatchDelete is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 []string
func (_e *Repository_Expecter) BatchDelete(_a0 interface{}, _a1 interface{}) *Repository_BatchDelete_Call {
	return &Repository_BatchDelete_Call{Call: _e.mock.On("BatchDelete", _a0, _a1)}
}

func (_c *Repository_BatchDelete_Call) Run(run func(_a0 context.Context, _a1 []string)) *Repository_BatchDelete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].([]string))
	})
	return _c
}

func (_c *Repository_BatchDelete_Call) Return(_a0 error) *Repository_BatchDelete_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Repository_BatchDelete_Call) RunAndReturn(run func(context.Context, []string) error) *Repository_BatchDelete_Call {
	_c.Call.Return(run)
	return _c
}

// BulkUpsert provides a mock function with given fields: _a0, _a1
func (_m *Repository) BulkUpsert(_a0 context.Context, _a1 []*domain.Resource) error {
	ret := _m.Called(_a0, _a1)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, []*domain.Resource) error); ok {
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
//   - _a0 context.Context
//   - _a1 []*domain.Resource
func (_e *Repository_Expecter) BulkUpsert(_a0 interface{}, _a1 interface{}) *Repository_BulkUpsert_Call {
	return &Repository_BulkUpsert_Call{Call: _e.mock.On("BulkUpsert", _a0, _a1)}
}

func (_c *Repository_BulkUpsert_Call) Run(run func(_a0 context.Context, _a1 []*domain.Resource)) *Repository_BulkUpsert_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].([]*domain.Resource))
	})
	return _c
}

func (_c *Repository_BulkUpsert_Call) Return(_a0 error) *Repository_BulkUpsert_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Repository_BulkUpsert_Call) RunAndReturn(run func(context.Context, []*domain.Resource) error) *Repository_BulkUpsert_Call {
	_c.Call.Return(run)
	return _c
}

// Delete provides a mock function with given fields: ctx, id
func (_m *Repository) Delete(ctx context.Context, id string) error {
	ret := _m.Called(ctx, id)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Repository_Delete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Delete'
type Repository_Delete_Call struct {
	*mock.Call
}

// Delete is a helper method to define mock.On call
//   - ctx context.Context
//   - id string
func (_e *Repository_Expecter) Delete(ctx interface{}, id interface{}) *Repository_Delete_Call {
	return &Repository_Delete_Call{Call: _e.mock.On("Delete", ctx, id)}
}

func (_c *Repository_Delete_Call) Run(run func(ctx context.Context, id string)) *Repository_Delete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *Repository_Delete_Call) Return(_a0 error) *Repository_Delete_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Repository_Delete_Call) RunAndReturn(run func(context.Context, string) error) *Repository_Delete_Call {
	_c.Call.Return(run)
	return _c
}

// Find provides a mock function with given fields: _a0, _a1
func (_m *Repository) Find(_a0 context.Context, _a1 domain.ListResourcesFilter) ([]*domain.Resource, error) {
	ret := _m.Called(_a0, _a1)

	var r0 []*domain.Resource
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, domain.ListResourcesFilter) ([]*domain.Resource, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, domain.ListResourcesFilter) []*domain.Resource); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*domain.Resource)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, domain.ListResourcesFilter) error); ok {
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
//   - _a0 context.Context
//   - _a1 domain.ListResourcesFilter
func (_e *Repository_Expecter) Find(_a0 interface{}, _a1 interface{}) *Repository_Find_Call {
	return &Repository_Find_Call{Call: _e.mock.On("Find", _a0, _a1)}
}

func (_c *Repository_Find_Call) Run(run func(_a0 context.Context, _a1 domain.ListResourcesFilter)) *Repository_Find_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(domain.ListResourcesFilter))
	})
	return _c
}

func (_c *Repository_Find_Call) Return(_a0 []*domain.Resource, _a1 error) *Repository_Find_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Repository_Find_Call) RunAndReturn(run func(context.Context, domain.ListResourcesFilter) ([]*domain.Resource, error)) *Repository_Find_Call {
	_c.Call.Return(run)
	return _c
}

// GetOne provides a mock function with given fields: ctx, id
func (_m *Repository) GetOne(ctx context.Context, id string) (*domain.Resource, error) {
	ret := _m.Called(ctx, id)

	var r0 *domain.Resource
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*domain.Resource, error)); ok {
		return rf(ctx, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *domain.Resource); ok {
		r0 = rf(ctx, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*domain.Resource)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, id)
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
//   - ctx context.Context
//   - id string
func (_e *Repository_Expecter) GetOne(ctx interface{}, id interface{}) *Repository_GetOne_Call {
	return &Repository_GetOne_Call{Call: _e.mock.On("GetOne", ctx, id)}
}

func (_c *Repository_GetOne_Call) Run(run func(ctx context.Context, id string)) *Repository_GetOne_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *Repository_GetOne_Call) Return(_a0 *domain.Resource, _a1 error) *Repository_GetOne_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Repository_GetOne_Call) RunAndReturn(run func(context.Context, string) (*domain.Resource, error)) *Repository_GetOne_Call {
	_c.Call.Return(run)
	return _c
}

// GetResourcesTotalCount provides a mock function with given fields: _a0, _a1
func (_m *Repository) GetResourcesTotalCount(_a0 context.Context, _a1 domain.ListResourcesFilter) (int64, error) {
	ret := _m.Called(_a0, _a1)

	var r0 int64
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, domain.ListResourcesFilter) (int64, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, domain.ListResourcesFilter) int64); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Get(0).(int64)
	}

	if rf, ok := ret.Get(1).(func(context.Context, domain.ListResourcesFilter) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Repository_GetResourcesTotalCount_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetResourcesTotalCount'
type Repository_GetResourcesTotalCount_Call struct {
	*mock.Call
}

// GetResourcesTotalCount is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 domain.ListResourcesFilter
func (_e *Repository_Expecter) GetResourcesTotalCount(_a0 interface{}, _a1 interface{}) *Repository_GetResourcesTotalCount_Call {
	return &Repository_GetResourcesTotalCount_Call{Call: _e.mock.On("GetResourcesTotalCount", _a0, _a1)}
}

func (_c *Repository_GetResourcesTotalCount_Call) Run(run func(_a0 context.Context, _a1 domain.ListResourcesFilter)) *Repository_GetResourcesTotalCount_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(domain.ListResourcesFilter))
	})
	return _c
}

func (_c *Repository_GetResourcesTotalCount_Call) Return(_a0 int64, _a1 error) *Repository_GetResourcesTotalCount_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Repository_GetResourcesTotalCount_Call) RunAndReturn(run func(context.Context, domain.ListResourcesFilter) (int64, error)) *Repository_GetResourcesTotalCount_Call {
	_c.Call.Return(run)
	return _c
}

// Update provides a mock function with given fields: _a0, _a1
func (_m *Repository) Update(_a0 context.Context, _a1 *domain.Resource) error {
	ret := _m.Called(_a0, _a1)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *domain.Resource) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Repository_Update_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Update'
type Repository_Update_Call struct {
	*mock.Call
}

// Update is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *domain.Resource
func (_e *Repository_Expecter) Update(_a0 interface{}, _a1 interface{}) *Repository_Update_Call {
	return &Repository_Update_Call{Call: _e.mock.On("Update", _a0, _a1)}
}

func (_c *Repository_Update_Call) Run(run func(_a0 context.Context, _a1 *domain.Resource)) *Repository_Update_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*domain.Resource))
	})
	return _c
}

func (_c *Repository_Update_Call) Return(_a0 error) *Repository_Update_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Repository_Update_Call) RunAndReturn(run func(context.Context, *domain.Resource) error) *Repository_Update_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewRepository interface {
	mock.TestingT
	Cleanup(func())
}

// NewRepository creates a new instance of Repository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewRepository(t mockConstructorTestingTNewRepository) *Repository {
	mock := &Repository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
