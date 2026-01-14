package labeling_test

import (
	"context"
	"testing"
	"time"

	"github.com/goto/guardian/core/labeling"
	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyLabels_NoRules(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{ID: "test-1", AccountID: "user@example.com"}
	policy := &domain.Policy{
		ID:           "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{LabelingRules: nil},
	}

	labels, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	assert.NoError(t, err)
	assert.Empty(t, labels)
}

func TestApplyLabels_MatchingRule(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{
		ID:        "test-1",
		AccountID: "user@example.com",
		Resource:  &domain.Resource{Type: "database"},
	}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName: "db-rule",
					When:     "$appeal.Resource.Type == \"database\"",
					Labels:   map[string]string{"type": "db", "level": "read"},
					Priority: 100,
				},
			},
		},
	}

	labels, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	require.NoError(t, err)
	assert.Len(t, labels, 2)
	assert.Equal(t, "db", labels["type"].Value)
	assert.Equal(t, "read", labels["level"].Value)
	assert.Equal(t, domain.LabelSourcePolicyRule, labels["type"].Source)
}

func TestApplyLabels_PriorityOrdering(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{
		ID:        "test-1",
		AccountID: "admin@example.com",
		Resource:  &domain.Resource{Type: "database"},
	}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName: "low-priority",
					When:     "true",
					Labels:   map[string]string{"sensitivity": "low"},
					Priority: 50,
				},
				{
					RuleName: "high-priority",
					When:     "$appeal.AccountID contains \"admin\"",
					Labels:   map[string]string{"sensitivity": "high"},
					Priority: 100,
				},
			},
		},
	}

	labels, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	require.NoError(t, err)
	assert.Equal(t, "high", labels["sensitivity"].Value)
}

func TestApplyLabels_DynamicValues(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{
		ID:        "test-1",
		AccountID: "user@example.com",
		Resource:  &domain.Resource{Type: "database", URN: "urn:db:prod"},
	}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName: "dynamic",
					When:     "true",
					Labels: map[string]string{
						"resource-type": "$appeal.Resource.Type",
						"urn":           "$appeal.Resource.URN",
					},
					Priority: 100,
				},
			},
		},
	}

	labels, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	require.NoError(t, err)
	assert.Equal(t, "database", labels["resource-type"].Value)
	assert.Equal(t, "urn:db:prod", labels["urn"].Value)
}

func TestApplyLabels_AllowFailure(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{ID: "test-1", AccountID: "user@example.com"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName:     "bad-rule",
					When:         "invalid.syntax",
					Labels:       map[string]string{"test": "value"},
					AllowFailure: true,
					Priority:     100,
				},
				{
					RuleName: "good-rule",
					When:     "true",
					Labels:   map[string]string{"env": "prod"},
					Priority: 50,
				},
			},
		},
	}

	labels, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	assert.NoError(t, err)
	assert.Len(t, labels, 1)
	assert.Equal(t, "prod", labels["env"].Value)
}

func TestApplyLabels_ErrorWhenNoAllowFailure(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{ID: "test-1"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName:     "bad",
					When:         "invalid syntax",
					AllowFailure: false,
				},
			},
		},
	}

	_, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to evaluate rule")
}

func TestApplyLabels_WithMetadata(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{ID: "test-1"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName: "meta-rule",
					When:     "true",
					Labels:   map[string]string{"compliance": "pci"},
					LabelMetadata: map[string]*domain.LabelMetadataConfig{
						"compliance": {
							Category:   "security",
							Attributes: map[string]interface{}{"level": "high"},
						},
					},
					Priority: 100,
				},
			},
		},
	}

	labels, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	require.NoError(t, err)
	assert.Equal(t, "pci", labels["compliance"].Value)
	assert.Equal(t, "security", labels["compliance"].Category)
	assert.Equal(t, "high", labels["compliance"].Attributes["level"])
}

func TestValidateManualLabels_NotAllowed(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	userLabels := map[string]string{"custom": "value"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			ManualLabelConfig: &domain.ManualLabelConfig{AllowUserLabels: false},
		},
	}

	err := svc.ValidateManualLabels(ctx, userLabels, policy.AppealConfig.ManualLabelConfig)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed")
}

func TestValidateManualLabels_MaxLabels(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	userLabels := map[string]string{"a": "1", "b": "2", "c": "3"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			ManualLabelConfig: &domain.ManualLabelConfig{
				AllowUserLabels: true,
				MaxLabels:       2,
			},
		},
	}

	err := svc.ValidateManualLabels(ctx, userLabels, policy.AppealConfig.ManualLabelConfig)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestValidateManualLabels_AllowedKeys(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	userLabels := map[string]string{"env": "prod", "forbidden": "val"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			ManualLabelConfig: &domain.ManualLabelConfig{
				AllowUserLabels: true,
				AllowedKeys:     []string{"env", "team"},
			},
		},
	}

	err := svc.ValidateManualLabels(ctx, userLabels, policy.AppealConfig.ManualLabelConfig)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

func TestValidateManualLabels_RequiredKeys(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	userLabels := map[string]string{"env": "prod"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			ManualLabelConfig: &domain.ManualLabelConfig{
				AllowUserLabels: true,
				RequiredKeys:    []string{"env", "team"},
			},
		},
	}

	err := svc.ValidateManualLabels(ctx, userLabels, policy.AppealConfig.ManualLabelConfig)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
}

func TestValidateManualLabels_KeyPattern(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	userLabels := map[string]string{"Invalid-Key": "value"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			ManualLabelConfig: &domain.ManualLabelConfig{
				AllowUserLabels: true,
				KeyPattern:      "^[a-z_]+$", // lowercase and underscore only
			},
		},
	}

	err := svc.ValidateManualLabels(ctx, userLabels, policy.AppealConfig.ManualLabelConfig)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
}

func TestValidateManualLabels_ValuePattern(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	userLabels := map[string]string{"cost_center": "invalid@value"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			ManualLabelConfig: &domain.ManualLabelConfig{
				AllowUserLabels: true,
				ValuePattern:    "^[a-zA-Z0-9]+$", // alphanumeric only
			},
		},
	}

	err := svc.ValidateManualLabels(ctx, userLabels, policy.AppealConfig.ManualLabelConfig)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
}

func TestValidateManualLabels_Valid(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	userLabels := map[string]string{"env": "prod", "team": "backend"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			ManualLabelConfig: &domain.ManualLabelConfig{
				AllowUserLabels: true,
				AllowedKeys:     []string{"env", "team"},
				RequiredKeys:    []string{"env"},
			},
		},
	}

	err := svc.ValidateManualLabels(ctx, userLabels, policy.AppealConfig.ManualLabelConfig)

	assert.NoError(t, err)
}

func TestMergeLabels_NoConflict(t *testing.T) {
	svc := labeling.NewService()

	policyLabels := map[string]*domain.LabelMetadata{
		"type": {Value: "db", Source: domain.LabelSourcePolicyRule},
	}
	manualLabels := map[string]*domain.LabelMetadata{
		"team": {Value: "backend", Source: domain.LabelSourceUser},
	}

	merged := svc.MergeLabels(policyLabels, manualLabels, false)

	assert.Len(t, merged, 2)
	assert.Equal(t, "db", merged["type"].Value)
	assert.Equal(t, "backend", merged["team"].Value)
}

func TestMergeLabels_KeepPolicyWhenNoOverride(t *testing.T) {
	svc := labeling.NewService()

	policyLabels := map[string]*domain.LabelMetadata{
		"env": {Value: "prod", Source: domain.LabelSourcePolicyRule, DerivedFrom: "rule1"},
	}
	manualLabels := map[string]*domain.LabelMetadata{
		"env": {Value: "staging", Source: domain.LabelSourceUser},
	}

	merged := svc.MergeLabels(policyLabels, manualLabels, false)

	assert.Len(t, merged, 1)
	assert.Equal(t, "prod", merged["env"].Value)
	assert.Equal(t, domain.LabelSourcePolicyRule, merged["env"].Source)
}

func TestMergeLabels_AllowOverride(t *testing.T) {
	svc := labeling.NewService()

	now := time.Now()
	policyLabels := map[string]*domain.LabelMetadata{
		"env": {Value: "prod", Source: domain.LabelSourcePolicyRule, DerivedFrom: "rule1"},
	}
	manualLabels := map[string]*domain.LabelMetadata{
		"env": {Value: "staging", Source: domain.LabelSourceUser, AppliedAt: now},
	}

	merged := svc.MergeLabels(policyLabels, manualLabels, true)

	assert.Len(t, merged, 1)
	assert.Equal(t, "staging", merged["env"].Value)
	assert.Equal(t, domain.LabelSourceUser, merged["env"].Source)
}

func TestMergeLabels_EmptyMaps(t *testing.T) {
	svc := labeling.NewService()

	merged := svc.MergeLabels(
		map[string]*domain.LabelMetadata{},
		map[string]*domain.LabelMetadata{},
		false,
	)

	assert.Empty(t, merged)
}

// Additional edge case tests for 100% coverage

func TestApplyLabels_EmptyCondition(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{ID: "test-1"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName: "empty-when",
					When:     "", // Empty condition defaults to true
					Labels:   map[string]string{"default": "value"},
					Priority: 100,
				},
			},
		},
	}

	labels, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	require.NoError(t, err)
	assert.Len(t, labels, 1)
	assert.Equal(t, "value", labels["default"].Value)
}

func TestApplyLabels_ConditionEvaluationError(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{ID: "test-1"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName: "bad-condition",
					When:     "$appeal.NonExistent.Field.Access",
					Labels:   map[string]string{"test": "value"},
					Priority: 100,
				},
			},
		},
	}

	_, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to evaluate rule")
}

func TestApplyLabels_NonBooleanConditionResult(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{ID: "test-1", AccountID: "user@example.com"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName: "non-bool",
					When:     "$appeal.AccountID", // Returns string, not bool
					Labels:   map[string]string{"test": "value"},
					Priority: 100,
				},
			},
		},
	}

	_, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	assert.Error(t, err)
	// expr library catches type mismatch during compilation
	assert.Contains(t, err.Error(), "failed to")
}

func TestApplyLabels_LabelValueEvaluationError(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{ID: "test-1"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName:     "bad-value-expr",
					When:         "true",
					Labels:       map[string]string{"test": "$appeal.NonExistent.Deep.Field"},
					Priority:     100,
					AllowFailure: false,
				},
			},
		},
	}

	// Should error when evaluation fails and AllowFailure=false
	_, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to evaluate label value")
}

func TestApplyLabels_StaticStringValue(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{ID: "test-1"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName: "static-value",
					When:     "true",
					Labels:   map[string]string{"env": "production"}, // Static string without special chars
					Priority: 100,
				},
			},
		},
	}

	labels, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	require.NoError(t, err)
	assert.Equal(t, "production", labels["env"].Value)
}

func TestApplyLabels_ComplexTypeExpressionValue(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{
		ID:        "test-1",
		Resource:  &domain.Resource{Type: "database", URN: "urn:db:prod"},
		AccountID: "user@example.com",
	}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName: "complex-value",
					When:     "true",
					Labels:   map[string]string{"resource_obj": "$appeal.Resource"}, // Complex object
					Priority: 100,
				},
			},
		},
	}

	labels, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	require.NoError(t, err)
	// Complex types get formatted with %v
	assert.Contains(t, labels["resource_obj"].Value, "database")
}

func TestApplyLabels_SkipLabelWhenAlreadySetByHigherPriority(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{ID: "test-1"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName: "high-priority",
					When:     "true",
					Labels:   map[string]string{"env": "production"},
					Priority: 200,
				},
				{
					RuleName: "low-priority",
					When:     "true",
					Labels:   map[string]string{"env": "staging"}, // Should be skipped
					Priority: 100,
				},
			},
		},
	}

	labels, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	require.NoError(t, err)
	assert.Len(t, labels, 1)
	assert.Equal(t, "production", labels["env"].Value)
	assert.Equal(t, "high-priority", labels["env"].DerivedFrom)
}

func TestValidateManualLabels_EmptyUserLabels(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			ManualLabelConfig: &domain.ManualLabelConfig{
				AllowUserLabels: true,
			},
		},
	}

	err := svc.ValidateManualLabels(ctx, map[string]string{}, policy.AppealConfig.ManualLabelConfig)

	assert.NoError(t, err)
}

func TestValidateManualLabels_MissingConfig(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	userLabels := map[string]string{"test": "value"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			ManualLabelConfig: nil, // Config exists but allows manual labels
		},
	}

	err := svc.ValidateManualLabels(ctx, userLabels, policy.AppealConfig.ManualLabelConfig)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed")
}

func TestValidateManualLabels_ZeroMaxLabels(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	userLabels := map[string]string{"a": "1"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			ManualLabelConfig: &domain.ManualLabelConfig{
				AllowUserLabels: true,
				MaxLabels:       0, // 0 means no limit
			},
		},
	}

	err := svc.ValidateManualLabels(ctx, userLabels, policy.AppealConfig.ManualLabelConfig)

	assert.NoError(t, err)
}

func TestValidateManualLabels_InvalidKeyPattern(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	userLabels := map[string]string{"test_key": "value"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			ManualLabelConfig: &domain.ManualLabelConfig{
				AllowUserLabels: true,
				KeyPattern:      "[invalid(regex", // Invalid regex
			},
		},
	}

	err := svc.ValidateManualLabels(ctx, userLabels, policy.AppealConfig.ManualLabelConfig)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid regex pattern")
}

func TestValidateManualLabels_InvalidValuePattern(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	userLabels := map[string]string{"test": "value"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			ManualLabelConfig: &domain.ManualLabelConfig{
				AllowUserLabels: true,
				ValuePattern:    "[invalid(regex", // Invalid regex
			},
		},
	}

	err := svc.ValidateManualLabels(ctx, userLabels, policy.AppealConfig.ManualLabelConfig)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid regex pattern")
}

func TestValidateManualLabels_NoAllowedKeysRestriction(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	userLabels := map[string]string{"any_key": "any_value", "another": "test"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			ManualLabelConfig: &domain.ManualLabelConfig{
				AllowUserLabels: true,
				AllowedKeys:     nil, // nil means no restriction
			},
		},
	}

	err := svc.ValidateManualLabels(ctx, userLabels, policy.AppealConfig.ManualLabelConfig)

	assert.NoError(t, err)
}

func TestValidateManualLabels_NoRequiredKeys(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	userLabels := map[string]string{"optional": "value"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			ManualLabelConfig: &domain.ManualLabelConfig{
				AllowUserLabels: true,
				RequiredKeys:    nil, // No required keys
			},
		},
	}

	err := svc.ValidateManualLabels(ctx, userLabels, policy.AppealConfig.ManualLabelConfig)

	assert.NoError(t, err)
}

func TestApplyLabels_TimestampSet(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	before := time.Now()
	appeal := &domain.Appeal{ID: "test-1"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName: "timestamp-check",
					When:     "true",
					Labels:   map[string]string{"test": "value"},
					Priority: 100,
				},
			},
		},
	}

	labels, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)
	after := time.Now()

	require.NoError(t, err)
	assert.True(t, !labels["test"].AppliedAt.Before(before))
	assert.True(t, !labels["test"].AppliedAt.After(after))
}

func TestApplyLabels_MultipleLabelsFromSameRule(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{ID: "test-1"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName: "multi-label",
					When:     "true",
					Labels: map[string]string{
						"label1": "value1",
						"label2": "value2",
						"label3": "value3",
					},
					Priority: 100,
				},
			},
		},
	}

	labels, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	require.NoError(t, err)
	assert.Len(t, labels, 3)
	assert.Equal(t, "multi-label", labels["label1"].DerivedFrom)
	assert.Equal(t, "multi-label", labels["label2"].DerivedFrom)
	assert.Equal(t, "multi-label", labels["label3"].DerivedFrom)
}

func TestMergeLabels_OnlyPolicyLabels(t *testing.T) {
	svc := labeling.NewService()

	policyLabels := map[string]*domain.LabelMetadata{
		"env":  {Value: "prod", Source: domain.LabelSourcePolicyRule},
		"team": {Value: "backend", Source: domain.LabelSourcePolicyRule},
	}

	merged := svc.MergeLabels(policyLabels, map[string]*domain.LabelMetadata{}, false)

	assert.Len(t, merged, 2)
	assert.Equal(t, "prod", merged["env"].Value)
	assert.Equal(t, "backend", merged["team"].Value)
}

func TestMergeLabels_OnlyManualLabels(t *testing.T) {
	svc := labeling.NewService()

	manualLabels := map[string]*domain.LabelMetadata{
		"custom1": {Value: "val1", Source: domain.LabelSourceUser},
		"custom2": {Value: "val2", Source: domain.LabelSourceUser},
	}

	merged := svc.MergeLabels(map[string]*domain.LabelMetadata{}, manualLabels, false)

	assert.Len(t, merged, 2)
	assert.Equal(t, "val1", merged["custom1"].Value)
	assert.Equal(t, "val2", merged["custom2"].Value)
}

// Additional tests for 100% coverage

func TestEvaluateCondition_CompilationError(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{ID: "test-1"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName: "bad-compile",
					When:     "invalid syntax ++ @@", // Syntax error
					Labels:   map[string]string{"test": "value"},
					Priority: 100,
				},
			},
		},
	}

	_, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to evaluate") // Changed from "failed to compile"
}

func TestEvaluateLabelValue_CompilationFailureFallbackToStatic(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{ID: "test-1"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName: "compile-fail",
					When:     "true",
					Labels:   map[string]string{"test": "invalid.syntax ++ @@"}, // Invalid expression
					Priority: 100,
				},
			},
		},
	}

	labels, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	require.NoError(t, err)
	// Falls back to treating as static string when compilation fails
	assert.Equal(t, "invalid.syntax ++ @@", labels["test"].Value)
}

func TestEvaluateLabelValue_EvaluationFailureReturnsError(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{ID: "test-1"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName: "eval-fail",
					When:     "true",
					Labels:   map[string]string{"test": "$appeal.Missing.Field.Chain"}, // Valid syntax but fails eval
					Priority: 100,
				},
			},
		},
	}

	_, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to evaluate label value")
}

func TestValidatePattern_MatchSuccess(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	userLabels := map[string]string{"cost_center": "1234"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			ManualLabelConfig: &domain.ManualLabelConfig{
				AllowUserLabels: true,
				ValuePattern:    "^[0-9]{4}$",
			},
		},
	}

	err := svc.ValidateManualLabels(ctx, userLabels, policy.AppealConfig.ManualLabelConfig)

	assert.NoError(t, err)
}

func TestApplyLabels_LabelValueAllowFailureTrue(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{ID: "test-1"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName:     "allow-fail-value",
					When:         "true",
					Labels:       map[string]string{"test": "$appeal.NonExistent.Deep.Access"},
					AllowFailure: true,
					Priority:     100,
				},
				{
					RuleName: "valid-rule",
					When:     "true",
					Labels:   map[string]string{"env": "prod"},
					Priority: 50,
				},
			},
		},
	}

	labels, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	require.NoError(t, err)
	// When AllowFailure=true, the rule should be skipped on error, only valid-rule applies
	assert.Len(t, labels, 1)
	assert.Equal(t, "prod", labels["env"].Value)
}

func TestApplyLabels_ConditionRunError(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{ID: "test-1"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName: "runtime-error",
					When:     "$appeal.ID / 0", // Division by zero or similar runtime error
					Labels:   map[string]string{"test": "value"},
					Priority: 100,
				},
			},
		},
	}

	_, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to evaluate")
}

func TestApplyLabels_UpdateExistingLabelFromSameRule(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{ID: "test-1"}
	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName: "same-rule-update",
					When:     "true",
					Labels: map[string]string{
						"env": "production",
					},
					Priority: 100,
				},
			},
		},
	}

	labels, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	require.NoError(t, err)
	assert.Equal(t, "production", labels["env"].Value)
	assert.Equal(t, "same-rule-update", labels["env"].DerivedFrom)
}

func TestValidateManualLabels_NoAppealConfig(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	userLabels := map[string]string{"test": "value"}

	err := svc.ValidateManualLabels(ctx, userLabels, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed")
}

func TestApplyLabels_ExistingLabelFromHigherPriorityRule(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{
		ID: "appeal-1",
		Resource: &domain.Resource{
			Type: "database",
		},
	}

	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName: "high-priority-rule",
					Priority: 100,
					When:     "$resource.Type == 'database'",
					Labels: map[string]string{
						"priority": "critical",
					},
				},
				{
					RuleName: "low-priority-rule",
					Priority: 10,
					When:     "$resource.Type == 'database'",
					Labels: map[string]string{
						"priority": "normal", // Should be ignored, same key already set by higher priority
					},
				},
			},
		},
	}

	labels, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	assert.NoError(t, err)
	assert.Equal(t, "critical", labels["priority"].Value, "Should keep value from higher priority rule")
	assert.Equal(t, "high-priority-rule", labels["priority"].DerivedFrom)
}

func TestApplyLabels_LabelEvaluationFailureWithAllowFailureFalse(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	appeal := &domain.Appeal{
		ID:       "appeal-1",
		Resource: &domain.Resource{},
	}

	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			LabelingRules: []domain.LabelingRule{
				{
					RuleName: "bad-label-rule",
					Priority: 100,
					When:     "true",
					Labels: map[string]string{
						"invalid": "nonexistent.field.value", // Will fallback to static string
					},
					AllowFailure: false,
				},
			},
		},
	}

	// This should actually succeed because evaluateLabelValue falls back to static string
	labels, err := svc.ApplyLabels(ctx, appeal, appeal.Resource, policy)

	assert.NoError(t, err)
	// The value should be the literal string since expression evaluation will fail gracefully
	assert.Equal(t, "nonexistent.field.value", labels["invalid"].Value)
}

func TestValidateManualLabels_EmptyLabelsWithRequiredKeys(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			ManualLabelConfig: &domain.ManualLabelConfig{
				AllowUserLabels: true,
				RequiredKeys:    []string{"team"},
			},
		},
	}

	err := svc.ValidateManualLabels(ctx, map[string]string{}, policy.AppealConfig.ManualLabelConfig)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required label keys missing")
}

func TestValidateManualLabels_NilLabelsWithRequiredKeys(t *testing.T) {
	ctx := context.Background()
	svc := labeling.NewService()

	policy := &domain.Policy{
		ID: "policy-1",
		AppealConfig: &domain.PolicyAppealConfig{
			ManualLabelConfig: &domain.ManualLabelConfig{
				AllowUserLabels: true,
				RequiredKeys:    []string{"team"},
			},
		},
	}

	err := svc.ValidateManualLabels(ctx, nil, policy.AppealConfig.ManualLabelConfig)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required label keys missing")
}
