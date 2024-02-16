// Code generated by mockery v2.20.0. DO NOT EDIT.

package mocks

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// AuditLogger is an autogenerated mock type for the auditLogger type
type AuditLogger struct {
	mock.Mock
}

type AuditLogger_Expecter struct {
	mock *mock.Mock
}

func (_m *AuditLogger) EXPECT() *AuditLogger_Expecter {
	return &AuditLogger_Expecter{mock: &_m.Mock}
}

// Log provides a mock function with given fields: ctx, action, data
func (_m *AuditLogger) Log(ctx context.Context, action string, data interface{}) error {
	ret := _m.Called(ctx, action, data)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, interface{}) error); ok {
		r0 = rf(ctx, action, data)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AuditLogger_Log_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Log'
type AuditLogger_Log_Call struct {
	*mock.Call
}

// Log is a helper method to define mock.On call
//   - ctx context.Context
//   - action string
//   - data interface{}
func (_e *AuditLogger_Expecter) Log(ctx interface{}, action interface{}, data interface{}) *AuditLogger_Log_Call {
	return &AuditLogger_Log_Call{Call: _e.mock.On("Log", ctx, action, data)}
}

func (_c *AuditLogger_Log_Call) Run(run func(ctx context.Context, action string, data interface{})) *AuditLogger_Log_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(interface{}))
	})
	return _c
}

func (_c *AuditLogger_Log_Call) Return(_a0 error) *AuditLogger_Log_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AuditLogger_Log_Call) RunAndReturn(run func(context.Context, string, interface{}) error) *AuditLogger_Log_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewAuditLogger interface {
	mock.TestingT
	Cleanup(func())
}

// NewAuditLogger creates a new instance of AuditLogger. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewAuditLogger(t mockConstructorTestingTNewAuditLogger) *AuditLogger {
	mock := &AuditLogger{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
