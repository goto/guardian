package maxcompute

import (
	"testing"

	"github.com/goto/guardian/domain"
)

func permissionConfig(resourceType string, permissions ...interface{}) *config {
	return &config{ProviderConfig: &domain.ProviderConfig{
		Credentials: credentials{
			AccessKeyID: "synthetic-id", AccessKeySecret: "synthetic-secret",
			RegionID: "ap-southeast-5", ProjectName: "test_project",
		},
		Resources: []*domain.ResourceConfig{{
			Type:  resourceType,
			Roles: []*domain.Role{{ID: "test", Name: "Test", Permissions: permissions}},
		}},
	}}
}

func TestConfigAcceptsTieredStorageTableActions(t *testing.T) {
	for _, action := range []string{
		"ReadLowFrequencyStorage", "ReadLowfrequencyStorage", "readlowfrequencystorage", "READLOWFREQUENCYSTORAGE",
		"ReadLongTermStorage", "ReadLongtermStorage", "readlongtermstorage", "READLONGTERMSTORAGE",
	} {
		t.Run(action, func(t *testing.T) {
			if err := permissionConfig(resourceTypeTable, action).validate(); err != nil {
				t.Fatalf("cold-read action rejected: %v", err)
			}
		})
	}
	if err := permissionConfig(resourceTypeTable, "Select", tableActionReadLowFrequencyStorage, tableActionReadLongTermStorage).validate(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigRejectsInvalidTableActions(t *testing.T) {
	for _, action := range []interface{}{"ReadColdStorage", "ReadLowFrequencyStorag", "odps:ReadLongTermStorage", "", 42} {
		if err := permissionConfig(resourceTypeTable, action).validate(); err == nil {
			t.Errorf("invalid action %v was accepted", action)
		}
	}
	if err := permissionConfig(resourceTypeTable).validate(); err == nil {
		t.Fatal("empty permission list was accepted")
	}
}

func TestConfigPreservesExistingTableActions(t *testing.T) {
	for _, action := range []string{"Describe", "Select", "Alter", "Update", "Drop", "ShowHistory", "All"} {
		if err := permissionConfig(resourceTypeTable, action).validate(); err != nil {
			t.Errorf("existing action %s rejected: %v", action, err)
		}
	}
}

func TestConfigAcceptsTieredStorageRoleNames(t *testing.T) {
	for _, test := range []struct {
		resourceType string
		permissions  []interface{}
	}{
		{resourceTypeProject, []interface{}{"lowfrequencystoragereader", "longtermstoragereader"}},
		{resourceTypeSchema, []interface{}{"schema_lowfrequencystoragereader", "schema_longtermstoragereader"}},
	} {
		if err := permissionConfig(test.resourceType, test.permissions...).validate(); err != nil {
			t.Errorf("%s role names rejected: %v", test.resourceType, err)
		}
	}
}
