// Code generated by mockery v2.20.0. DO NOT EDIT.

package mocks

import (
	context "context"

	domain "github.com/goto/guardian/domain"
	mock "github.com/stretchr/testify/mock"
)

// ProviderService is an autogenerated mock type for the providerService type
type ProviderService struct {
	mock.Mock
}

type ProviderService_Expecter struct {
	mock *mock.Mock
}

func (_m *ProviderService) EXPECT() *ProviderService_Expecter {
	return &ProviderService_Expecter{mock: &_m.Mock}
}

// GetOne provides a mock function with given fields: ctx, pType, urn
func (_m *ProviderService) GetOne(ctx context.Context, pType string, urn string) (*domain.Provider, error) {
	ret := _m.Called(ctx, pType, urn)

	var r0 *domain.Provider
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (*domain.Provider, error)); ok {
		return rf(ctx, pType, urn)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *domain.Provider); ok {
		r0 = rf(ctx, pType, urn)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*domain.Provider)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, pType, urn)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ProviderService_GetOne_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetOne'
type ProviderService_GetOne_Call struct {
	*mock.Call
}

// GetOne is a helper method to define mock.On call
//   - ctx context.Context
//   - pType string
//   - urn string
func (_e *ProviderService_Expecter) GetOne(ctx interface{}, pType interface{}, urn interface{}) *ProviderService_GetOne_Call {
	return &ProviderService_GetOne_Call{Call: _e.mock.On("GetOne", ctx, pType, urn)}
}

func (_c *ProviderService_GetOne_Call) Run(run func(ctx context.Context, pType string, urn string)) *ProviderService_GetOne_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *ProviderService_GetOne_Call) Return(_a0 *domain.Provider, _a1 error) *ProviderService_GetOne_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ProviderService_GetOne_Call) RunAndReturn(run func(context.Context, string, string) (*domain.Provider, error)) *ProviderService_GetOne_Call {
	_c.Call.Return(run)
	return _c
}

// ValidateAppeal provides a mock function with given fields: _a0, _a1, _a2, _a3
func (_m *ProviderService) ValidateAppeal(_a0 context.Context, _a1 *domain.Appeal, _a2 *domain.Provider, _a3 *domain.Policy) error {
	ret := _m.Called(_a0, _a1, _a2, _a3)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *domain.Appeal, *domain.Provider, *domain.Policy) error); ok {
		r0 = rf(_a0, _a1, _a2, _a3)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ProviderService_ValidateAppeal_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ValidateAppeal'
type ProviderService_ValidateAppeal_Call struct {
	*mock.Call
}

// ValidateAppeal is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *domain.Appeal
//   - _a2 *domain.Provider
//   - _a3 *domain.Policy
func (_e *ProviderService_Expecter) ValidateAppeal(_a0 interface{}, _a1 interface{}, _a2 interface{}, _a3 interface{}) *ProviderService_ValidateAppeal_Call {
	return &ProviderService_ValidateAppeal_Call{Call: _e.mock.On("ValidateAppeal", _a0, _a1, _a2, _a3)}
}

func (_c *ProviderService_ValidateAppeal_Call) Run(run func(_a0 context.Context, _a1 *domain.Appeal, _a2 *domain.Provider, _a3 *domain.Policy)) *ProviderService_ValidateAppeal_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*domain.Appeal), args[2].(*domain.Provider), args[3].(*domain.Policy))
	})
	return _c
}

func (_c *ProviderService_ValidateAppeal_Call) Return(_a0 error) *ProviderService_ValidateAppeal_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ProviderService_ValidateAppeal_Call) RunAndReturn(run func(context.Context, *domain.Appeal, *domain.Provider, *domain.Policy) error) *ProviderService_ValidateAppeal_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewProviderService interface {
	mock.TestingT
	Cleanup(func())
}

// NewProviderService creates a new instance of ProviderService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewProviderService(t mockConstructorTestingTNewProviderService) *ProviderService {
	mock := &ProviderService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
