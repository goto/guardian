package domain

import (
	"net/url"
	"strings"
)

// NotificationResourceWebURL exposes only the provider's public browser link.
func NotificationResourceWebURL(resource *Resource) string {
	if resource == nil || resource.ProviderType != "gitlab" || (resource.Type != "project" && resource.Type != "group") {
		return ""
	}
	metadata, _ := resource.Details["__metadata"].(map[string]interface{})
	value, _ := metadata["web_url"].(string)
	return NotificationBrowserURL(value)
}

func NotificationBrowserURL(value string) string {
	if value == "" || len(value) > 2048 || strings.ContainsAny(value, " \t\r\n") {
		return ""
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return ""
	}
	return value
}

// NotificationAccountDisplayName projects only the RAM display name, never the
// rest of the identity/HR metadata. The account ID remains the access identity.
func NotificationAccountDisplayName(accountID string, details map[string]interface{}) string {
	if !strings.HasPrefix(accountID, "RAM$") {
		return ""
	}
	_, userID, ok := strings.Cut(accountID, ":")
	if !ok || userID == "" {
		return ""
	}
	metadata, _ := details["__policy_metadata"].(map[string]interface{})
	user, _ := metadata["ram_user_details"].(map[string]interface{})
	if id, _ := user["user_id"].(string); id != "" && id != userID {
		return ""
	}
	name, _ := user["display_name"].(string)
	if strings.TrimSpace(name) == "" {
		name, _ = user["user_name"].(string)
	}
	name = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(name), " ("+accountID+")"))
	if name == accountID || strings.Contains(name, "RAM$") || len([]rune(name)) > 400 {
		return ""
	}
	return name
}

// WithNotificationDisplayContext adds optional public presentation fields to a
// freshly constructed notification map without changing its identity or scope.
func WithNotificationDisplayContext(variables map[string]interface{}, resource *Resource, appeal *Appeal) map[string]interface{} {
	if link := NotificationResourceWebURL(resource); link != "" {
		variables["resource_web_url"] = link
	}
	if appeal != nil && variables["account_id"] == appeal.AccountID {
		if name := NotificationAccountDisplayName(appeal.AccountID, appeal.Details); name != "" {
			variables["account_display_name"] = name
		}
	}
	return variables
}
