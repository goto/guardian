// Code generated by mockery v2.10.0. DO NOT EDIT.

package mocks

import (
	context "context"

	grant "github.com/goto/guardian/core/grant"
	domain "github.com/goto/guardian/domain"

	mock "github.com/stretchr/testify/mock"
)

// GrantService is an autogenerated mock type for the grantService type
type GrantService struct {
	mock.Mock
}

// List provides a mock function with given fields: _a0, _a1
func (_m *GrantService) List(_a0 context.Context, _a1 domain.ListGrantsFilter) ([]domain.Grant, error) {
	ret := _m.Called(_a0, _a1)

	var r0 []domain.Grant
	if rf, ok := ret.Get(0).(func(context.Context, domain.ListGrantsFilter) []domain.Grant); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]domain.Grant)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, domain.ListGrantsFilter) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Revoke provides a mock function with given fields: ctx, id, actor, reason, opts
func (_m *GrantService) Revoke(ctx context.Context, id string, actor string, reason string, opts ...grant.Option) (*domain.Grant, error) {
	_va := make([]interface{}, len(opts))
	for _i := range opts {
		_va[_i] = opts[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, id, actor, reason)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *domain.Grant
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, ...grant.Option) *domain.Grant); ok {
		r0 = rf(ctx, id, actor, reason, opts...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*domain.Grant)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, ...grant.Option) error); ok {
		r1 = rf(ctx, id, actor, reason, opts...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
