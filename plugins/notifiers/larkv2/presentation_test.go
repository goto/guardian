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

func TestV2DurationUsesRawValueWithoutInferringPermanent(t *testing.T) {
	for _, duration := range []string{"", "0h", "90d"} {
		input := map[string]interface{}{"duration": "Permanent", "requested_duration": duration}
		if got := presentationVariables(input)["duration"]; got != duration {
			t.Fatalf("duration = %v, want %q", got, duration)
		}
		if input["duration"] != "Permanent" {
			t.Fatal("legacy value mutated")
		}
	}
}

func TestUnusedGrantBatchRetainsBoundedPublicContext(t *testing.T) {
	var grants []map[string]interface{}
	for i := 0; i < 100; i++ {
		grants = append(grants, map[string]interface{}{"resource": map[string]interface{}{"name": "Reporting", "urn": "reporting", "details": "PRIVATE_CANARY"}, "role": "reader", "account_id": "bot@example.com", "details": "PRIVATE_CANARY"})
	}
	result := presentationVariables(map[string]interface{}{"dormant_grants": grants, "period": "720h", "retain_duration": "168h"})
	data, _ := json.Marshal(result)
	if result["unused_grants_count"] != 100 || len(result["unused_grants"].([]map[string]interface{})) != 5 || !strings.Contains(string(data), "Reporting") || strings.Contains(string(data), "PRIVATE") {
		t.Fatal("unused grants lost context or exposed private data")
	}
	if len(data) > 10000 {
		t.Fatal("unbounded batch payload")
	}
}

func TestLongPublicTextCannotPreventNotificationDelivery(t *testing.T) {
	input := map[string]interface{}{"body": strings.Repeat("界", 30000)}
	data, err := json.Marshal(presentationVariables(input))
	if err != nil || len(data) > 4000 {
		t.Fatal("long comment exceeds delivery budget")
	}
	if len([]rune(input["body"].(string))) != 30000 {
		t.Fatal("original comment was truncated")
	}
}

func TestPackageCreationPresentationUsesBusinessFieldsOnly(t *testing.T) {
	result := presentationVariables(map[string]interface{}{"resource_type": "package-create", "package_creation": map[string]interface{}{"name": "Analytics", "description": "Reporting access", "created_by": "creator@example.com", "type": "bot-only", "functional_roles": []string{"data-reader"}, "private": "PRIVATE_CANARY"}, "details": map[string]interface{}{"__policy_metadata": "PRIVATE_CANARY"}})
	body, _ := json.Marshal(result)
	if !strings.Contains(string(body), "Analytics") || strings.Contains(string(body), "PRIVATE_CANARY") {
		t.Fatal("creation context lost or private metadata leaked")
	}
}

func TestMalformedCreationRolesAreMarkedIncomplete(t *testing.T) {
	result := presentationVariables(map[string]interface{}{"resource_type": "package-create", "package_creation": map[string]interface{}{"functional_roles": "unexpected"}})
	if result["package_creation"].(map[string]interface{})["incomplete"] != true {
		t.Fatal("malformed roles were presented as complete")
	}
}
