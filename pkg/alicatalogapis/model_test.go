package alicatalogapis

import "testing"

func TestRoleBindingPolicyToUserFormatPreservesBuiltinRoles(t *testing.T) {
	policy := &RoleBindingPolicy{
		Bindings: []*RoleBindingPolicyBindings{
			{Role: "roles/admin", Members: []string{"RAM$1:role/a"}},
			{Role: "namespaces/5866780647397444/roles/administrator", Members: []string{"RAM$1:role/b"}},
		},
	}

	policy.toUserFormat()

	if got := policy.Bindings[0].Role; got != "roles/admin" {
		t.Fatalf("builtin role changed to %q", got)
	}
	if got := policy.Bindings[1].Role; got != "administrator" {
		t.Fatalf("custom role was not shortened: %q", got)
	}
}

func TestRoleBindingPolicyToAliFormatPreservesBuiltinRolesAndRemovesInvalidMembers(t *testing.T) {
	policy := &RoleBindingPolicy{
		Bindings: []*RoleBindingPolicyBindings{
			{
				Role: "roles/admin",
				Members: []string{
					"INVALID$v4_301523129623737122",
					"RAM$5866780647397444:role/aliyunreservedsso-administratoraccess",
				},
			},
			{
				Role:    "roles/viewer",
				Members: []string{"INVALID$only"},
			},
			{
				Role:    "administrator",
				Members: []string{"RAM$5866780647397444:role/guardian-bot"},
			},
		},
	}

	policy.toAliFormat("5866780647397444")

	if len(policy.Bindings) != 2 {
		t.Fatalf("expected 2 bindings after dropping INVALID$-only role, got %d: %#v", len(policy.Bindings), policy.Bindings)
	}
	if got := policy.Bindings[0].Role; got != "roles/admin" {
		t.Fatalf("builtin role changed to %q", got)
	}
	if got := policy.Bindings[0].Members; len(got) != 1 || got[0] != "RAM$5866780647397444:role/aliyunreservedsso-administratoraccess" {
		t.Fatalf("invalid member was not removed: %#v", got)
	}
	if got := policy.Bindings[1].Role; got != "namespaces/5866780647397444/roles/administrator" {
		t.Fatalf("custom role was not qualified: %q", got)
	}
}
