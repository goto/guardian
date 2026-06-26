package alicloud_ram

import (
	"encoding/json"
	"testing"

	"github.com/bearaujus/bptr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makePolicyDoc(principals []string) string {
	p := RAMPolicy{
		Version: "1",
		Statement: []Statement{
			{
				Action: "sts:AssumeRole",
				Effect: "Allow",
				Principal: Principal{
					RAM: principals,
				},
			},
		},
	}
	b, _ := json.Marshal(p)
	return string(b)
}

func parsePolicy(t *testing.T, doc string) RAMPolicy {
	t.Helper()
	var p RAMPolicy
	require.NoError(t, json.Unmarshal([]byte(doc), &p))
	return p
}

// ── GrantSTSTrustPolicyRole ──────────────────────────────────────────────────

func TestGrantSTSTrustPolicyRole_AddsNewPrincipal(t *testing.T) {
	doc := makePolicyDoc([]string{"acs:ram::5348956882036640:user/existing-user"})
	role := Role{AssumeRolePolicyDocument: bptr.FromStringNilAble(doc)}

	result, err := GrantSTSTrustPolicyRole(role, "acs:ram::5348956882036640:user/test-bot-user-rba1")

	require.NoError(t, err)
	policy := parsePolicy(t, result)
	assert.Contains(t, policy.Statement[0].Principal.RAM, "acs:ram::5348956882036640:user/test-bot-user-rba1")
	assert.Contains(t, policy.Statement[0].Principal.RAM, "acs:ram::5348956882036640:user/existing-user")
	assert.Len(t, policy.Statement[0].Principal.RAM, 2)
}

func TestGrantSTSTrustPolicyRole_NoDuplicateOnReGrant(t *testing.T) {
	accountID := "acs:ram::5348956882036640:user/test-bot-user-rba1"
	doc := makePolicyDoc([]string{accountID})
	role := Role{AssumeRolePolicyDocument: bptr.FromStringNilAble(doc)}

	result, err := GrantSTSTrustPolicyRole(role, accountID)

	require.NoError(t, err)
	policy := parsePolicy(t, result)
	assert.Len(t, policy.Statement[0].Principal.RAM, 1)
}

func TestGrantSTSTrustPolicyRole_EmptyPrincipals(t *testing.T) {
	doc := makePolicyDoc([]string{})
	role := Role{AssumeRolePolicyDocument: bptr.FromStringNilAble(doc)}

	result, err := GrantSTSTrustPolicyRole(role, "acs:ram::5348956882036640:user/test-bot-user-rba1")

	require.NoError(t, err)
	policy := parsePolicy(t, result)
	assert.Equal(t, []string{"acs:ram::5348956882036640:user/test-bot-user-rba1"}, policy.Statement[0].Principal.RAM)
}

func TestGrantSTSTrustPolicyRole_NilPolicyDocument(t *testing.T) {
	role := Role{AssumeRolePolicyDocument: nil}

	_, err := GrantSTSTrustPolicyRole(role, "acs:ram::5348956882036640:user/test-bot-user-rba1")

	assert.Error(t, err)
}

func TestGrantSTSTrustPolicyRole_InvalidPolicyJSON(t *testing.T) {
	role := Role{AssumeRolePolicyDocument: bptr.FromStringNilAble("not-json")}

	_, err := GrantSTSTrustPolicyRole(role, "acs:ram::5348956882036640:user/test-bot-user-rba1")

	assert.Error(t, err)
}

// ── RevokeSTSTrustPolicyRole ─────────────────────────────────────────────────

func TestRevokeSTSTrustPolicyRole_RemovesPrincipal(t *testing.T) {
	accountID := "acs:ram::5348956882036640:user/test-bot-user-rba1"
	doc := makePolicyDoc([]string{"acs:ram::5348956882036640:user/other-user", accountID})
	role := Role{AssumeRolePolicyDocument: bptr.FromStringNilAble(doc)}

	result, err := RevokeSTSTrustPolicyRole(role, accountID)

	require.NoError(t, err)
	policy := parsePolicy(t, result)
	assert.NotContains(t, policy.Statement[0].Principal.RAM, accountID)
	assert.Contains(t, policy.Statement[0].Principal.RAM, "acs:ram::5348956882036640:user/other-user")
}

func TestRevokeSTSTrustPolicyRole_NoOpWhenPrincipalAbsent(t *testing.T) {
	doc := makePolicyDoc([]string{"acs:ram::5348956882036640:user/other-user"})
	role := Role{AssumeRolePolicyDocument: bptr.FromStringNilAble(doc)}

	result, err := RevokeSTSTrustPolicyRole(role, "acs:ram::5348956882036640:user/nonexistent")

	require.NoError(t, err)
	policy := parsePolicy(t, result)
	assert.Len(t, policy.Statement[0].Principal.RAM, 1)
}

func TestRevokeSTSTrustPolicyRole_LastPrincipalResultsInEmptyList(t *testing.T) {
	accountID := "acs:ram::5348956882036640:user/only-user"
	doc := makePolicyDoc([]string{accountID})
	role := Role{AssumeRolePolicyDocument: bptr.FromStringNilAble(doc)}

	result, err := RevokeSTSTrustPolicyRole(role, accountID)

	require.NoError(t, err)
	policy := parsePolicy(t, result)
	assert.Empty(t, policy.Statement[0].Principal.RAM)
}

func TestRevokeSTSTrustPolicyRole_NilPolicyDocument(t *testing.T) {
	role := Role{AssumeRolePolicyDocument: nil}

	_, err := RevokeSTSTrustPolicyRole(role, "acs:ram::5348956882036640:user/test")

	assert.Error(t, err)
}

func TestRevokeSTSTrustPolicyRole_InvalidPolicyJSON(t *testing.T) {
	role := Role{AssumeRolePolicyDocument: bptr.FromStringNilAble("not-json")}

	_, err := RevokeSTSTrustPolicyRole(role, "acs:ram::5348956882036640:user/test")

	assert.Error(t, err)
}

// ── Version and Action preserved ─────────────────────────────────────────────

func TestGrantSTSTrustPolicyRole_PreservesVersionAndAction(t *testing.T) {
	doc := makePolicyDoc([]string{})
	role := Role{AssumeRolePolicyDocument: bptr.FromStringNilAble(doc)}

	result, err := GrantSTSTrustPolicyRole(role, "acs:ram::5348956882036640:user/test-bot-user-rba1")

	require.NoError(t, err)
	policy := parsePolicy(t, result)
	assert.Equal(t, "1", policy.Version)
	assert.Equal(t, "sts:AssumeRole", policy.Statement[0].Action)
	assert.Equal(t, "Allow", policy.Statement[0].Effect)
}
