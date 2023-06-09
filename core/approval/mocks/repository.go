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

// AddApprover provides a mock function with given fields: _a0, _a1
func (_m *Repository) AddApprover(_a0 context.Context, _a1 *domain.Approver) error {
	ret := _m.Called(_a0, _a1)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *domain.Approver) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Repository_AddApprover_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AddApprover'
type Repository_AddApprover_Call struct {
	*mock.Call
}

// AddApprover is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *domain.Approver
func (_e *Repository_Expecter) AddApprover(_a0 interface{}, _a1 interface{}) *Repository_AddApprover_Call {
	return &Repository_AddApprover_Call{Call: _e.mock.On("AddApprover", _a0, _a1)}
}

func (_c *Repository_AddApprover_Call) Run(run func(_a0 context.Context, _a1 *domain.Approver)) *Repository_AddApprover_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*domain.Approver))
	})
	return _c
}

func (_c *Repository_AddApprover_Call) Return(_a0 error) *Repository_AddApprover_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Repository_AddApprover_Call) RunAndReturn(run func(context.Context, *domain.Approver) error) *Repository_AddApprover_Call {
	_c.Call.Return(run)
	return _c
}

// BulkInsert provides a mock function with given fields: _a0, _a1
func (_m *Repository) BulkInsert(_a0 context.Context, _a1 []*domain.Approval) error {
	ret := _m.Called(_a0, _a1)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, []*domain.Approval) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Repository_BulkInsert_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'BulkInsert'
type Repository_BulkInsert_Call struct {
	*mock.Call
}

// BulkInsert is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 []*domain.Approval
func (_e *Repository_Expecter) BulkInsert(_a0 interface{}, _a1 interface{}) *Repository_BulkInsert_Call {
	return &Repository_BulkInsert_Call{Call: _e.mock.On("BulkInsert", _a0, _a1)}
}

func (_c *Repository_BulkInsert_Call) Run(run func(_a0 context.Context, _a1 []*domain.Approval)) *Repository_BulkInsert_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].([]*domain.Approval))
	})
	return _c
}

func (_c *Repository_BulkInsert_Call) Return(_a0 error) *Repository_BulkInsert_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Repository_BulkInsert_Call) RunAndReturn(run func(context.Context, []*domain.Approval) error) *Repository_BulkInsert_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteApprover provides a mock function with given fields: ctx, approvalID, email
func (_m *Repository) DeleteApprover(ctx context.Context, approvalID string, email string) error {
	ret := _m.Called(ctx, approvalID, email)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, approvalID, email)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Repository_DeleteApprover_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteApprover'
type Repository_DeleteApprover_Call struct {
	*mock.Call
}

// DeleteApprover is a helper method to define mock.On call
//   - ctx context.Context
//   - approvalID string
//   - email string
func (_e *Repository_Expecter) DeleteApprover(ctx interface{}, approvalID interface{}, email interface{}) *Repository_DeleteApprover_Call {
	return &Repository_DeleteApprover_Call{Call: _e.mock.On("DeleteApprover", ctx, approvalID, email)}
}

func (_c *Repository_DeleteApprover_Call) Run(run func(ctx context.Context, approvalID string, email string)) *Repository_DeleteApprover_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *Repository_DeleteApprover_Call) Return(_a0 error) *Repository_DeleteApprover_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Repository_DeleteApprover_Call) RunAndReturn(run func(context.Context, string, string) error) *Repository_DeleteApprover_Call {
	_c.Call.Return(run)
	return _c
}

// ListApprovals provides a mock function with given fields: _a0, _a1
func (_m *Repository) ListApprovals(_a0 context.Context, _a1 *domain.ListApprovalsFilter) ([]*domain.Approval, error) {
	ret := _m.Called(_a0, _a1)

	var r0 []*domain.Approval
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *domain.ListApprovalsFilter) ([]*domain.Approval, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *domain.ListApprovalsFilter) []*domain.Approval); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*domain.Approval)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *domain.ListApprovalsFilter) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Repository_ListApprovals_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListApprovals'
type Repository_ListApprovals_Call struct {
	*mock.Call
}

// ListApprovals is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *domain.ListApprovalsFilter
func (_e *Repository_Expecter) ListApprovals(_a0 interface{}, _a1 interface{}) *Repository_ListApprovals_Call {
	return &Repository_ListApprovals_Call{Call: _e.mock.On("ListApprovals", _a0, _a1)}
}

func (_c *Repository_ListApprovals_Call) Run(run func(_a0 context.Context, _a1 *domain.ListApprovalsFilter)) *Repository_ListApprovals_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*domain.ListApprovalsFilter))
	})
	return _c
}

func (_c *Repository_ListApprovals_Call) Return(_a0 []*domain.Approval, _a1 error) *Repository_ListApprovals_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Repository_ListApprovals_Call) RunAndReturn(run func(context.Context, *domain.ListApprovalsFilter) ([]*domain.Approval, error)) *Repository_ListApprovals_Call {
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
