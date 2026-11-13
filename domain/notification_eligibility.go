package domain

// NotificationSuppressionReason identifies package implementation details that
// must not generate separate routine user notifications. It does not affect
// provisioning, revocation, approval requirements, or operational alerts.
// Unknown and ungrouped grants stay visible: a missing appeal ID alone does not
// distinguish a dependency from imported, independently managed access.
func (g Grant) NotificationSuppressionReason() string {
	return technicalPackageAccessReason(g.Resource, g.AccountType, g.GroupID, g.GroupType, g.Role)
}

func (a Appeal) NotificationSuppressionReason() string {
	return technicalPackageAccessReason(a.Resource, a.AccountType, a.GroupID, a.GroupType, a.Role)
}

func technicalPackageAccessReason(resource *Resource, accountType, groupID, groupType, role string) string {
	if groupID == "" || resource == nil {
		return ""
	}
	// The membership is the actionable parent, even though its group type is
	// shared with the underlying CloudSSO/trust grants.
	if resource.ProviderType == "guardian" && resource.Type == "package" {
		return ""
	}
	switch groupType {
	case "package_access_bot_ram_role":
		if accountType == "ram_role" {
			return "package bot role resource copy"
		}
	case "package_access_bot_ram_user":
		if accountType == "ram_user" {
			return "package bot user resource copy"
		}
	case "package_user":
		if resource.ProviderType == "alicloud_sso" && resource.Type == "group" && accountType == "sso_user" && role == "member" {
			return "package CloudSSO membership dependency"
		}
		if resource.ProviderType == "alicloud_ram" && resource.Type == "ram_role" && accountType == "ram_user" && role == "STSTrustPolicy" {
			return "package bot trust dependency"
		}
	}
	return ""
}
