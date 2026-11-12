package larkv2

import (
	"encoding/json"
	"github.com/goto/guardian/domain"
	"strings"
	"testing"
)

func TestV2PresentationOmitsPrivateAndOversizedPolicyMetadata(t *testing.T) {
	input := map[string]interface{}{
		"resource_id": "package-id", "resource_name": "Example package", "role": "reader",
		"details":         map[string]interface{}{"__policy_metadata": map[string]interface{}{"private": strings.Repeat("PRIVATE_CANARY", 10000)}, "__policy_questions": map[string]interface{}{"reason_to_access": "Investigate reporting."}},
		"unknown_private": "PRIVATE_OTHER",
	}
	result := presentationVariables(input)
	data, _ := json.Marshal(result)
	if strings.Contains(string(data), "PRIVATE_") || len(data) > 1024 {
		t.Fatal("private policy data entered delivery payload")
	}
	if result["reason_to_access"] != "Investigate reporting." || result["resource_id"] != "package-id" {
		t.Fatal("decision context was dropped")
	}
	if _, ok := input["details"]; !ok {
		t.Fatal("legacy/shared variables were mutated")
	}
}

func TestOwnerChangeUsesOnlyPublicGrantContext(t *testing.T) {
	grant := &domain.Grant{AccountID: "bot@example.com", AccountType: "bot", Role: "reader", Resource: &domain.Resource{ID: "package-id", Name: "Example package", URN: "example-package", Type: "package", ProviderType: "guardian"}}
	result := presentationVariables(map[string]interface{}{"grant": grant, "new_owner": "owner@example.com"})
	if result["resource_id"] != "package-id" || result["resource_type"] != "package" || result["new_owner"] != "owner@example.com" {
		t.Fatal("package link context was not preserved")
	}
	if _, ok := result["grant"]; ok {
		t.Fatal("raw grant object was forwarded")
	}
}
