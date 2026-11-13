package larkv2

import "github.com/goto/guardian/domain"

// presentationVariables keeps private policy/HR data out of v2 delivery payloads.
// Criteria and legacy notifiers continue to receive the original notification.
func presentationVariables(input map[string]interface{}) map[string]interface{} {
	output := map[string]interface{}{}
	for _, key := range []string{
		"resource_id", "resource_display_name", "resource_name", "resource_urn", "resource_type", "provider_type",
		"group_id", "group_type", "requestor", "appeal_created_by", "account_id", "account_type", "role", "duration", "appeal_id", "approval_step", "created_at",
		"reason", "revoke_reason", "reason_to_access", "comment", "body", "comment_created_by", "comment_id",
		"period", "retain_duration", "start_date_formatted", "pending_approvals_count", "expiration_date", "expiration_date_formatted", "previous_owner", "old_owner", "new_owner",
	} {
		if value, ok := input[key]; ok {
			output[key] = value
		}
	}
	if duration, ok := input["requested_duration"].(string); ok {
		output["duration"] = duration
	}
	if details, ok := input["details"].(map[string]interface{}); ok {
		questions, _ := details["__policy_questions"].(map[string]interface{})
		for _, key := range []string{"reason_to_access", "justification"} {
			if value, ok := questions[key].(string); ok && value != "" {
				if output["reason_to_access"] == nil {
					output["reason_to_access"] = value
				}
				break
			}
		}
		if output["reason_to_access"] == nil {
			if value, ok := details["reason_to_access"].(string); ok {
				output["reason_to_access"] = value
			}
		}
	}
	// The unused-access producer sends a batch, not one grant. Keep only bounded public summaries.
	if grants, ok := input["dormant_grants"].([]map[string]interface{}); ok {
		output["unused_grants_count"] = len(grants)
		var summaries []map[string]interface{}
		for i, grant := range grants {
			if i == 5 {
				break
			}
			summary := map[string]interface{}{}
			resource, _ := grant["resource"].(map[string]interface{})
			for dst, src := range map[string]string{"resource_display_name": "name", "resource_urn": "urn", "resource_id": "id", "provider_type": "provider_type", "resource_type": "type"} {
				if value, ok := resource[src].(string); ok {
					summary[dst] = presentationPreview(value)
				}
			}
			for _, key := range []string{"account_id", "role", "appeal_id", "group_id", "group_type", "account_type"} {
				if value, ok := grant[key].(string); ok {
					summary[key] = presentationPreview(value)
				}
			}
			summaries = append(summaries, summary)
		}
		output["unused_grants"] = summaries
	}
	if input["resource_type"] == "package-create" {
		creation, _ := input["package_creation"].(map[string]interface{})
		if creation == nil {
			creation, _ = input["details"].(map[string]interface{})
		}
		safe := map[string]interface{}{}
		for _, key := range []string{"name", "description", "created_by", "type"} {
			if value, ok := creation[key].(string); ok {
				limit := 401
				if key == "description" {
					limit = 1001
				}
				runes := []rune(value)
				if len(runes) > limit {
					value = string(runes[:limit])
				}
				safe[key] = value
			}
		}
		var roles []string
		switch values := creation["functional_roles"].(type) {
		case []string:
			roles = append([]string(nil), values...)
		case []interface{}:
			for _, value := range values {
				if role, ok := value.(string); ok {
					roles = append(roles, role)
				} else {
					safe["incomplete"] = true
				}
			}
		case nil:
		default:
			safe["incomplete"] = true
		}
		if len(roles) > 8 {
			roles = roles[:8]
			safe["incomplete"] = true
		}
		for i, role := range roles {
			if len([]rune(role)) > 120 {
				roles[i] = string([]rune(role)[:120])
				safe["incomplete"] = true
			}
		}
		safe["functional_roles"] = roles
		output["package_creation"] = safe
	}
	// Compatibility for integrations that supply a typed grant rather than flat resource fields.
	var grant *domain.Grant
	switch value := input["grant"].(type) {
	case *domain.Grant:
		grant = value
	case domain.Grant:
		grant = &value
	}
	if grant != nil {
		if grant.Resource != nil {
			output["resource_id"] = grant.Resource.ID
			output["resource_display_name"] = grant.Resource.Name
			output["resource_urn"] = grant.Resource.URN
			output["resource_type"] = grant.Resource.Type
			output["provider_type"] = grant.Resource.ProviderType
		}
		output["account_id"] = grant.AccountID
		output["account_type"] = grant.AccountType
		output["role"] = grant.Role
	}
	// Leave one extra rune so the worker marks these as shortened previews. Full text stays in Guardian.
	for _, key := range []string{"reason", "revoke_reason", "reason_to_access", "comment", "body"} {
		if value, ok := output[key].(string); ok {
			runes := []rune(value)
			if len(runes) > 1001 {
				output[key] = string(runes[:1001])
			}
		}
	}
	return output
}

func presentationPreview(value string) string {
	runes := []rune(value)
	if len(runes) > 400 {
		return string(runes[:400]) + "…"
	}
	return value
}
