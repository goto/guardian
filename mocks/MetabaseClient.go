// Code generated by mockery 2.9.0. DO NOT EDIT.

package mocks

import (
	metabase "github.com/odpf/guardian/plugins/providers/metabase"
	mock "github.com/stretchr/testify/mock"
)

// MetabaseClient is an autogenerated mock type for the MetabaseClient type
type MetabaseClient struct {
	mock.Mock
}

// GetCollections provides a mock function with given fields:
func (_m *MetabaseClient) GetCollections() ([]*metabase.Collection, error) {
	ret := _m.Called()

	var r0 []*metabase.Collection
	if rf, ok := ret.Get(0).(func() []*metabase.Collection); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*metabase.Collection)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetDatabases provides a mock function with given fields:
func (_m *MetabaseClient) GetDatabases() ([]*metabase.Database, error) {
	ret := _m.Called()

	var r0 []*metabase.Database
	if rf, ok := ret.Get(0).(func() []*metabase.Database); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*metabase.Database)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GrantCollectionAccess provides a mock function with given fields: resource, user, role
func (_m *MetabaseClient) GrantCollectionAccess(resource *metabase.Collection, user string, role string) error {
	ret := _m.Called(resource, user, role)

	var r0 error
	if rf, ok := ret.Get(0).(func(*metabase.Collection, string, string) error); ok {
		r0 = rf(resource, user, role)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GrantDatabaseAccess provides a mock function with given fields: resource, user, role
func (_m *MetabaseClient) GrantDatabaseAccess(resource *metabase.Database, user string, role string) error {
	ret := _m.Called(resource, user, role)

	var r0 error
	if rf, ok := ret.Get(0).(func(*metabase.Database, string, string) error); ok {
		r0 = rf(resource, user, role)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RevokeCollectionAccess provides a mock function with given fields: resource, user, role
func (_m *MetabaseClient) RevokeCollectionAccess(resource *metabase.Collection, user string, role string) error {
	ret := _m.Called(resource, user, role)

	var r0 error
	if rf, ok := ret.Get(0).(func(*metabase.Collection, string, string) error); ok {
		r0 = rf(resource, user, role)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RevokeDatabaseAccess provides a mock function with given fields: resource, user, role
func (_m *MetabaseClient) RevokeDatabaseAccess(resource *metabase.Database, user string, role string) error {
	ret := _m.Called(resource, user, role)

	var r0 error
	if rf, ok := ret.Get(0).(func(*metabase.Database, string, string) error); ok {
		r0 = rf(resource, user, role)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}