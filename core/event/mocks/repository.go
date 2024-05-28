// Code generated by mockery v2.33.0. DO NOT EDIT.

package mocks

import (
	context "context"

	audit "github.com/goto/salt/audit"

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

// List provides a mock function with given fields: _a0, _a1
func (_m *Repository) List(_a0 context.Context, _a1 *domain.ListAuditLogFilter) ([]*audit.Log, error) {
	ret := _m.Called(_a0, _a1)

	var r0 []*audit.Log
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *domain.ListAuditLogFilter) ([]*audit.Log, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *domain.ListAuditLogFilter) []*audit.Log); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*audit.Log)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *domain.ListAuditLogFilter) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Repository_List_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'List'
type Repository_List_Call struct {
	*mock.Call
}

// List is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *domain.ListAuditLogFilter
func (_e *Repository_Expecter) List(_a0 interface{}, _a1 interface{}) *Repository_List_Call {
	return &Repository_List_Call{Call: _e.mock.On("List", _a0, _a1)}
}

func (_c *Repository_List_Call) Run(run func(_a0 context.Context, _a1 *domain.ListAuditLogFilter)) *Repository_List_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*domain.ListAuditLogFilter))
	})
	return _c
}

func (_c *Repository_List_Call) Return(_a0 []*audit.Log, _a1 error) *Repository_List_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Repository_List_Call) RunAndReturn(run func(context.Context, *domain.ListAuditLogFilter) ([]*audit.Log, error)) *Repository_List_Call {
	_c.Call.Return(run)
	return _c
}

// NewRepository creates a new instance of Repository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *Repository {
	mock := &Repository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}