package larkv2

import "github.com/goto/guardian/domain"

// presentationVariables keeps private policy/HR data out of v2 delivery payloads.
// Criteria and legacy notifiers continue to receive the original notification.
func presentationVariables(input map[string]interface{}) map[string]interface{} {
	output := map[string]interface{}{}
	for _, key := range []string{
		"resource_id", "resource_display_name", "resource_name", "resource_urn", "resource_type", "provider_type",
		"requestor", "appeal_created_by", "account_id", "account_type", "role", "duration", "appeal_id", "approval_step", "created_at",
		"reason", "revoke_reason", "reason_to_access", "comment", "body", "comment_created_by", "comment_id",
		"pending_approvals_count", "expiration_date", "expiration_date_formatted", "previous_owner", "old_owner", "new_owner",
	} {
		if value, ok := input[key]; ok {
			output[key] = value
		}
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
	// Owner-change notifications use the grant object rather than flat resource fields.
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
	return output
}
