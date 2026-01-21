// Code generated manually. DO NOT EDIT.

package mocks

import (
	"context"

	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/mock"
)

// LabelingService is a manual mock type for the labelingService interface
type LabelingService struct {
	mock.Mock
}

type LabelingService_Expecter struct {
	mock *mock.Mock
}

func (_m *LabelingService) EXPECT() *LabelingService_Expecter {
	return &LabelingService_Expecter{mock: &_m.Mock}
}

// ApplyLabels provides a mock function with given fields: ctx, appeal, resource, policy
func (_m *LabelingService) ApplyLabels(ctx context.Context, appeal *domain.Appeal, resource *domain.Resource, policy *domain.Policy) (map[string]*domain.LabelMetadata, error) {
	ret := _m.Called(ctx, appeal, resource, policy)

	if len(ret) == 0 {
		panic("no return value specified for ApplyLabels")
	}

	var r0 map[string]*domain.LabelMetadata
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *domain.Appeal, *domain.Resource, *domain.Policy) (map[string]*domain.LabelMetadata, error)); ok {
		return rf(ctx, appeal, resource, policy)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *domain.Appeal, *domain.Resource, *domain.Policy) map[string]*domain.LabelMetadata); ok {
		r0 = rf(ctx, appeal, resource, policy)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]*domain.LabelMetadata)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *domain.Appeal, *domain.Resource, *domain.Policy) error); ok {
		r1 = rf(ctx, appeal, resource, policy)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LabelingService_ApplyLabels_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ApplyLabels'
type LabelingService_ApplyLabels_Call struct {
	*mock.Call
}

// ApplyLabels is a helper method to define mock.On call
//   - ctx context.Context
//   - appeal *domain.Appeal
//   - resource *domain.Resource
//   - policy *domain.Policy
func (_e *LabelingService_Expecter) ApplyLabels(ctx interface{}, appeal interface{}, resource interface{}, policy interface{}) *LabelingService_ApplyLabels_Call {
	return &LabelingService_ApplyLabels_Call{Call: _e.mock.On("ApplyLabels", ctx, appeal, resource, policy)}
}

func (_c *LabelingService_ApplyLabels_Call) Run(run func(ctx context.Context, appeal *domain.Appeal, resource *domain.Resource, policy *domain.Policy)) *LabelingService_ApplyLabels_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*domain.Appeal), args[2].(*domain.Resource), args[3].(*domain.Policy))
	})
	return _c
}

func (_c *LabelingService_ApplyLabels_Call) Return(_a0 map[string]*domain.LabelMetadata, _a1 error) *LabelingService_ApplyLabels_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *LabelingService_ApplyLabels_Call) RunAndReturn(run func(context.Context, *domain.Appeal, *domain.Resource, *domain.Policy) (map[string]*domain.LabelMetadata, error)) *LabelingService_ApplyLabels_Call {
	_c.Call.Return(run)
	return _c
}

// ValidateUserLabels provides a mock function with given fields: ctx, labels, config
func (_m *LabelingService) ValidateUserLabels(ctx context.Context, labels map[string]string, config *domain.UserLabelConfig) error {
	ret := _m.Called(ctx, labels, config)

	if len(ret) == 0 {
		panic("no return value specified for ValidateUserLabels")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, map[string]string, *domain.UserLabelConfig) error); ok {
		r0 = rf(ctx, labels, config)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// LabelingService_ValidateUserLabels_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ValidateUserLabels'
type LabelingService_ValidateUserLabels_Call struct {
	*mock.Call
}

// ValidateUserLabels is a helper method to define mock.On call
//   - ctx context.Context
//   - labels map[string]string
//   - config *domain.UserLabelConfig
func (_e *LabelingService_Expecter) ValidateUserLabels(ctx interface{}, labels interface{}, config interface{}) *LabelingService_ValidateUserLabels_Call {
	return &LabelingService_ValidateUserLabels_Call{Call: _e.mock.On("ValidateUserLabels", ctx, labels, config)}
}

func (_c *LabelingService_ValidateUserLabels_Call) Run(run func(ctx context.Context, labels map[string]string, config *domain.UserLabelConfig)) *LabelingService_ValidateUserLabels_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(map[string]string), args[2].(*domain.UserLabelConfig))
	})
	return _c
}

func (_c *LabelingService_ValidateUserLabels_Call) Return(_a0 error) *LabelingService_ValidateUserLabels_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *LabelingService_ValidateUserLabels_Call) RunAndReturn(run func(context.Context, map[string]string, *domain.UserLabelConfig) error) *LabelingService_ValidateUserLabels_Call {
	_c.Call.Return(run)
	return _c
}

// MergeLabels provides a mock function with given fields: policyLabels, manualLabels, allowOverride
func (_m *LabelingService) MergeLabels(policyLabels map[string]*domain.LabelMetadata, manualLabels map[string]*domain.LabelMetadata, allowOverride bool) map[string]*domain.LabelMetadata {
	ret := _m.Called(policyLabels, manualLabels, allowOverride)

	if len(ret) == 0 {
		panic("no return value specified for MergeLabels")
	}

	var r0 map[string]*domain.LabelMetadata
	if rf, ok := ret.Get(0).(func(map[string]*domain.LabelMetadata, map[string]*domain.LabelMetadata, bool) map[string]*domain.LabelMetadata); ok {
		r0 = rf(policyLabels, manualLabels, allowOverride)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]*domain.LabelMetadata)
		}
	}

	return r0
}

// LabelingService_MergeLabels_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MergeLabels'
type LabelingService_MergeLabels_Call struct {
	*mock.Call
}

// MergeLabels is a helper method to define mock.On call
//   - policyLabels map[string]*domain.LabelMetadata
//   - manualLabels map[string]*domain.LabelMetadata
//   - allowOverride bool
func (_e *LabelingService_Expecter) MergeLabels(policyLabels interface{}, manualLabels interface{}, allowOverride interface{}) *LabelingService_MergeLabels_Call {
	return &LabelingService_MergeLabels_Call{Call: _e.mock.On("MergeLabels", policyLabels, manualLabels, allowOverride)}
}

func (_c *LabelingService_MergeLabels_Call) Run(run func(policyLabels map[string]*domain.LabelMetadata, manualLabels map[string]*domain.LabelMetadata, allowOverride bool)) *LabelingService_MergeLabels_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(map[string]*domain.LabelMetadata), args[1].(map[string]*domain.LabelMetadata), args[2].(bool))
	})
	return _c
}

func (_c *LabelingService_MergeLabels_Call) Return(_a0 map[string]*domain.LabelMetadata) *LabelingService_MergeLabels_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *LabelingService_MergeLabels_Call) RunAndReturn(run func(map[string]*domain.LabelMetadata, map[string]*domain.LabelMetadata, bool) map[string]*domain.LabelMetadata) *LabelingService_MergeLabels_Call {
	_c.Call.Return(run)
	return _c
}

// NewLabelingService creates a new instance of LabelingService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewLabelingService(t interface {
	mock.TestingT
	Cleanup(func())
}) *LabelingService {
	mock := &LabelingService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
