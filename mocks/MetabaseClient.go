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

func (_m *MetabaseClient) GetGroups() ([]*metabase.Group, metabase.ResourceGroupDetails, metabase.ResourceGroupDetails, error) {
	ret := _m.Called()

	var r0 []*metabase.Group
	if rf, ok := ret.Get(0).(func() []*metabase.Group); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*metabase.Group)
		}
	}

	var r1 map[string][]map[string]interface{}
	if rf, ok := ret.Get(1).(func() map[string][]map[string]interface{}); ok {
		r1 = rf()
	} else {
		r1 = ret.Get(1).(map[string][]map[string]interface{})
	}

	var r2 map[string][]map[string]interface{}
	if rf, ok := ret.Get(2).(func() map[string][]map[string]interface{}); ok {
		r2 = rf()
	} else {
		r2 = ret.Get(2).(map[string][]map[string]interface{})
	}

	var r3 error
	if rf, ok := ret.Get(3).(func() error); ok {
		r3 = rf()
	} else {
		r3 = ret.Error(3)
	}

	return r0, r1, r2, r3
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
func (_m *MetabaseClient) GrantDatabaseAccess(resource *metabase.Database, user string, role string, groups map[string]*metabase.Group) error {
	ret := _m.Called(resource, user, role, groups)

	var r0 error
	if rf, ok := ret.Get(0).(func(*metabase.Database, string, string, map[string]*metabase.Group) error); ok {
		r0 = rf(resource, user, role, groups)
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
