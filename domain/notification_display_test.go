package domain

import "testing"

func TestNotificationDisplayContext(t *testing.T) {
	resource := &Resource{ProviderType: "gitlab", Type: "project", Details: map[string]interface{}{"__metadata": map[string]interface{}{"web_url": "https://gitlab.example.test/team/repository", "private": "PRIVATE_CANARY"}}}
	appeal := &Appeal{AccountID: "RAM$123:456", Details: map[string]interface{}{"__policy_metadata": map[string]interface{}{"ram_user_details": map[string]interface{}{"user_id": "456", "display_name": "monitoring (RAM$123:456)", "email": "PRIVATE_CANARY"}}}}
	variables := WithNotificationDisplayContext(map[string]interface{}{"account_id": appeal.AccountID}, resource, appeal)
	if variables["resource_web_url"] != "https://gitlab.example.test/team/repository" || variables["account_display_name"] != "monitoring" || len(variables) != 3 {
		t.Fatalf("unexpected display projection: %v", variables)
	}
	if got := WithNotificationDisplayContext(map[string]interface{}{"account_id": "RAM$123:999"}, resource, appeal); got["account_display_name"] != nil {
		t.Fatal("name attached to a different grant account")
	}
	user := appeal.Details["__policy_metadata"].(map[string]interface{})["ram_user_details"].(map[string]interface{})
	user["user_id"] = "999"
	if NotificationAccountDisplayName(appeal.AccountID, appeal.Details) != "" {
		t.Fatal("mismatched metadata identity accepted")
	}
	user["user_id"] = "456"
	user["display_name"] = ""
	user["user_name"] = "monitoring-user"
	if NotificationAccountDisplayName(appeal.AccountID, appeal.Details) != "monitoring-user" {
		t.Fatal("missing username fallback")
	}
	resource.ProviderType = "maxcompute"
	if NotificationResourceWebURL(resource) != "" {
		t.Fatal("non-GitLab metadata used as a GitLab link")
	}
}

func TestNotificationBrowserURLValidation(t *testing.T) {
	for _, value := range []string{"javascript:alert(1)", "//gitlab.example.test/a", "https://user:secret@gitlab.example.test/a", "https://gitlab.example.test/a?token=secret", "https://gitlab.example.test/a#fragment", "https:///a", "https://gitlab.example.test/a\n"} {
		if NotificationBrowserURL(value) != "" {
			t.Errorf("accepted unsafe browser URL %q", value)
		}
	}
	for _, value := range []string{"https://gitlab.example.test/team/repo", "http://gitlab.example.test:8080/team"} {
		if NotificationBrowserURL(value) != value {
			t.Errorf("lost valid browser URL %q", value)
		}
	}
}
