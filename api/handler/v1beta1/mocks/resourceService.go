// Code generated by mockery v2.47.0. DO NOT EDIT.

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

// BatchDelete provides a mock function with given fields: _a0, _a1
func (_m *ResourceService) BatchDelete(_a0 context.Context, _a1 []string) error {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for BatchDelete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, []string) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ResourceService_BatchDelete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'BatchDelete'
type ResourceService_BatchDelete_Call struct {
	*mock.Call
}

// BatchDelete is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 []string
func (_e *ResourceService_Expecter) BatchDelete(_a0 interface{}, _a1 interface{}) *ResourceService_BatchDelete_Call {
	return &ResourceService_BatchDelete_Call{Call: _e.mock.On("BatchDelete", _a0, _a1)}
}

func (_c *ResourceService_BatchDelete_Call) Run(run func(_a0 context.Context, _a1 []string)) *ResourceService_BatchDelete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].([]string))
	})
	return _c
}

func (_c *ResourceService_BatchDelete_Call) Return(_a0 error) *ResourceService_BatchDelete_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ResourceService_BatchDelete_Call) RunAndReturn(run func(context.Context, []string) error) *ResourceService_BatchDelete_Call {
	_c.Call.Return(run)
	return _c
}

// BulkUpsert provides a mock function with given fields: _a0, _a1
func (_m *ResourceService) BulkUpsert(_a0 context.Context, _a1 []*domain.Resource) error {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for BulkUpsert")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, []*domain.Resource) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ResourceService_BulkUpsert_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'BulkUpsert'
type ResourceService_BulkUpsert_Call struct {
	*mock.Call
}

// BulkUpsert is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 []*domain.Resource
func (_e *ResourceService_Expecter) BulkUpsert(_a0 interface{}, _a1 interface{}) *ResourceService_BulkUpsert_Call {
	return &ResourceService_BulkUpsert_Call{Call: _e.mock.On("BulkUpsert", _a0, _a1)}
}

func (_c *ResourceService_BulkUpsert_Call) Run(run func(_a0 context.Context, _a1 []*domain.Resource)) *ResourceService_BulkUpsert_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].([]*domain.Resource))
	})
	return _c
}

func (_c *ResourceService_BulkUpsert_Call) Return(_a0 error) *ResourceService_BulkUpsert_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ResourceService_BulkUpsert_Call) RunAndReturn(run func(context.Context, []*domain.Resource) error) *ResourceService_BulkUpsert_Call {
	_c.Call.Return(run)
	return _c
}

// Delete provides a mock function with given fields: _a0, _a1
func (_m *ResourceService) Delete(_a0 context.Context, _a1 string) error {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ResourceService_Delete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Delete'
type ResourceService_Delete_Call struct {
	*mock.Call
}

// Delete is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 string
func (_e *ResourceService_Expecter) Delete(_a0 interface{}, _a1 interface{}) *ResourceService_Delete_Call {
	return &ResourceService_Delete_Call{Call: _e.mock.On("Delete", _a0, _a1)}
}

func (_c *ResourceService_Delete_Call) Run(run func(_a0 context.Context, _a1 string)) *ResourceService_Delete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *ResourceService_Delete_Call) Return(_a0 error) *ResourceService_Delete_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ResourceService_Delete_Call) RunAndReturn(run func(context.Context, string) error) *ResourceService_Delete_Call {
	_c.Call.Return(run)
	return _c
}

// Find provides a mock function with given fields: _a0, _a1
func (_m *ResourceService) Find(_a0 context.Context, _a1 domain.ListResourcesFilter) ([]*domain.Resource, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for Find")
	}

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

// ResourceService_Find_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Find'
type ResourceService_Find_Call struct {
	*mock.Call
}

// Find is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 domain.ListResourcesFilter
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

func (_c *ResourceService_Find_Call) RunAndReturn(run func(context.Context, domain.ListResourcesFilter) ([]*domain.Resource, error)) *ResourceService_Find_Call {
	_c.Call.Return(run)
	return _c
}

// Get provides a mock function with given fields: _a0, _a1
func (_m *ResourceService) Get(_a0 context.Context, _a1 *domain.ResourceIdentifier) (*domain.Resource, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for Get")
	}

	var r0 *domain.Resource
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *domain.ResourceIdentifier) (*domain.Resource, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *domain.ResourceIdentifier) *domain.Resource); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*domain.Resource)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *domain.ResourceIdentifier) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ResourceService_Get_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Get'
type ResourceService_Get_Call struct {
	*mock.Call
}

// Get is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *domain.ResourceIdentifier
func (_e *ResourceService_Expecter) Get(_a0 interface{}, _a1 interface{}) *ResourceService_Get_Call {
	return &ResourceService_Get_Call{Call: _e.mock.On("Get", _a0, _a1)}
}

func (_c *ResourceService_Get_Call) Run(run func(_a0 context.Context, _a1 *domain.ResourceIdentifier)) *ResourceService_Get_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*domain.ResourceIdentifier))
	})
	return _c
}

func (_c *ResourceService_Get_Call) Return(_a0 *domain.Resource, _a1 error) *ResourceService_Get_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ResourceService_Get_Call) RunAndReturn(run func(context.Context, *domain.ResourceIdentifier) (*domain.Resource, error)) *ResourceService_Get_Call {
	_c.Call.Return(run)
	return _c
}

// GetOne provides a mock function with given fields: _a0, _a1
func (_m *ResourceService) GetOne(_a0 context.Context, _a1 string) (*domain.Resource, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for GetOne")
	}

	var r0 *domain.Resource
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*domain.Resource, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *domain.Resource); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*domain.Resource)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ResourceService_GetOne_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetOne'
type ResourceService_GetOne_Call struct {
	*mock.Call
}

// GetOne is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 string
func (_e *ResourceService_Expecter) GetOne(_a0 interface{}, _a1 interface{}) *ResourceService_GetOne_Call {
	return &ResourceService_GetOne_Call{Call: _e.mock.On("GetOne", _a0, _a1)}
}

func (_c *ResourceService_GetOne_Call) Run(run func(_a0 context.Context, _a1 string)) *ResourceService_GetOne_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *ResourceService_GetOne_Call) Return(_a0 *domain.Resource, _a1 error) *ResourceService_GetOne_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ResourceService_GetOne_Call) RunAndReturn(run func(context.Context, string) (*domain.Resource, error)) *ResourceService_GetOne_Call {
	_c.Call.Return(run)
	return _c
}

// GetResourcesTotalCount provides a mock function with given fields: _a0, _a1
func (_m *ResourceService) GetResourcesTotalCount(_a0 context.Context, _a1 domain.ListResourcesFilter) (int64, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for GetResourcesTotalCount")
	}

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

// ResourceService_GetResourcesTotalCount_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetResourcesTotalCount'
type ResourceService_GetResourcesTotalCount_Call struct {
	*mock.Call
}

// GetResourcesTotalCount is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 domain.ListResourcesFilter
func (_e *ResourceService_Expecter) GetResourcesTotalCount(_a0 interface{}, _a1 interface{}) *ResourceService_GetResourcesTotalCount_Call {
	return &ResourceService_GetResourcesTotalCount_Call{Call: _e.mock.On("GetResourcesTotalCount", _a0, _a1)}
}

func (_c *ResourceService_GetResourcesTotalCount_Call) Run(run func(_a0 context.Context, _a1 domain.ListResourcesFilter)) *ResourceService_GetResourcesTotalCount_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(domain.ListResourcesFilter))
	})
	return _c
}

func (_c *ResourceService_GetResourcesTotalCount_Call) Return(_a0 int64, _a1 error) *ResourceService_GetResourcesTotalCount_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ResourceService_GetResourcesTotalCount_Call) RunAndReturn(run func(context.Context, domain.ListResourcesFilter) (int64, error)) *ResourceService_GetResourcesTotalCount_Call {
	_c.Call.Return(run)
	return _c
}

// Update provides a mock function with given fields: _a0, _a1
func (_m *ResourceService) Update(_a0 context.Context, _a1 *domain.Resource) error {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for Update")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *domain.Resource) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ResourceService_Update_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Update'
type ResourceService_Update_Call struct {
	*mock.Call
}

// Update is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *domain.Resource
func (_e *ResourceService_Expecter) Update(_a0 interface{}, _a1 interface{}) *ResourceService_Update_Call {
	return &ResourceService_Update_Call{Call: _e.mock.On("Update", _a0, _a1)}
}

func (_c *ResourceService_Update_Call) Run(run func(_a0 context.Context, _a1 *domain.Resource)) *ResourceService_Update_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*domain.Resource))
	})
	return _c
}

func (_c *ResourceService_Update_Call) Return(_a0 error) *ResourceService_Update_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ResourceService_Update_Call) RunAndReturn(run func(context.Context, *domain.Resource) error) *ResourceService_Update_Call {
	_c.Call.Return(run)
	return _c
}

// NewResourceService creates a new instance of ResourceService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewResourceService(t interface {
	mock.TestingT
	Cleanup(func())
}) *ResourceService {
	mock := &ResourceService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
