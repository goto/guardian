package domain

import "testing"

func TestTechnicalPackageNotificationClassification(t *testing.T) {
	tests := []struct {
		name, provider, resourceType, accountType, groupType, role string
		quiet                                                      bool
	}{
		{"sso child", "alicloud_sso", "group", "sso_user", "package_user", "member", true},
		{"trust child", "alicloud_ram", "ram_role", "ram_user", "package_user", "STSTrustPolicy", true},
		{"role copy", "maxcompute", "table", "ram_role", "package_access_bot_ram_role", "viewer", true},
		{"access config copy", "alicloud_ram", "account", "ram_role", "package_access_bot_ram_role", "ReadOnlyAccess", true},
		{"bot user copy", "maxcompute", "schema", "ram_user", "package_access_bot_ram_user", "viewer", true},
		{"human membership", "guardian", "package", "user", "package_user", "member", false},
		{"bot membership", "guardian", "package", "bot", "package_user", "member", false},
		{"package resource", "maxcompute", "table", "ram_role", "package_access", "viewer", false},
		{"logical bot package resource", "maxcompute", "table", "package", "package_access", "viewer", false},
		{"managed package resource", "maxcompute", "project", "ram_role", "package_managed_access", "admin", false},
		{"legacy package resource", "maxcompute", "table", "ram_role", "package_resource", "viewer", false},
		{"direct sso", "alicloud_sso", "group", "sso_user", "", "member", false},
		{"direct trust", "alicloud_ram", "ram_role", "ram_user", "", "STSTrustPolicy", false},
		{"direct role", "maxcompute", "project", "ram_role", "", "dataviewer", false},
		{"functional role", "custom_http", "functional_role", "package", "", "member", false},
		{"unknown child", "other", "group", "user", "package_user", "member", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, appealID := range []string{"", "child-appeal"} {
				g := Grant{Resource: &Resource{ProviderType: tt.provider, Type: tt.resourceType}, AccountType: tt.accountType, GroupID: "package-id", GroupType: tt.groupType, Role: tt.role, AppealID: appealID}
				if got := g.NotificationSuppressionReason() != ""; got != tt.quiet {
					t.Fatalf("has appeal %v: quiet=%v, want %v", appealID != "", got, tt.quiet)
				}
				a := Appeal{Resource: g.Resource, AccountType: g.AccountType, GroupID: g.GroupID, GroupType: g.GroupType, Role: g.Role}
				if a.NotificationSuppressionReason() != g.NotificationSuppressionReason() {
					t.Fatal("appeal and grant classifications differ")
				}
				g.GroupID = ""
				if g.NotificationSuppressionReason() != "" {
					t.Fatal("missing package linkage must not hide access")
				}
			}
		})
	}
	g := Grant{Source: GrantSourceImport, Resource: &Resource{ProviderType: "maxcompute", Type: "project"}, Role: "member", IsPermanent: true}
	if g.NotificationSuppressionReason() != "" {
		t.Fatal("standalone imported grant hidden")
	}
	if (Grant{}).NotificationSuppressionReason() != "" {
		t.Fatal("unknown grant hidden")
	}
}
