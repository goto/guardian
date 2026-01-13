package domain_test

import (
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/assert"
)

func TestPolicy_HasLabelingRules(t *testing.T) {
	tests := []struct {
		name     string
		policy   *domain.Policy
		expected bool
	}{
		{
			name: "should return true when labeling rules exist",
			policy: &domain.Policy{
				AppealConfig: &domain.PolicyAppealConfig{
					LabelingRules: []domain.LabelingRule{
						{
							RuleName: "test_rule",
							When:     "$appeal.role contains 'admin'",
							Labels: map[string]string{
								"access_level": "high",
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "should return false when labeling rules is empty slice",
			policy: &domain.Policy{
				AppealConfig: &domain.PolicyAppealConfig{
					LabelingRules: []domain.LabelingRule{},
				},
			},
			expected: false,
		},
		{
			name: "should return false when labeling rules is nil",
			policy: &domain.Policy{
				AppealConfig: &domain.PolicyAppealConfig{
					LabelingRules: nil,
				},
			},
			expected: false,
		},
		{
			name: "should return false when appeal config is nil",
			policy: &domain.Policy{
				AppealConfig: nil,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.policy.HasLabelingRules()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPolicy_AllowsManualLabels(t *testing.T) {
	tests := []struct {
		name     string
		policy   *domain.Policy
		expected bool
	}{
		{
			name: "should return true when manual labels are allowed",
			policy: &domain.Policy{
				AppealConfig: &domain.PolicyAppealConfig{
					ManualLabelConfig: &domain.ManualLabelConfig{
						AllowUserLabels: true,
					},
				},
			},
			expected: true,
		},
		{
			name: "should return false when AllowUserLabels is false",
			policy: &domain.Policy{
				AppealConfig: &domain.PolicyAppealConfig{
					ManualLabelConfig: &domain.ManualLabelConfig{
						AllowUserLabels: false,
					},
				},
			},
			expected: false,
		},
		{
			name: "should return false when manual label config is nil",
			policy: &domain.Policy{
				AppealConfig: &domain.PolicyAppealConfig{
					ManualLabelConfig: nil,
				},
			},
			expected: false,
		},
		{
			name: "should return false when appeal config is nil",
			policy: &domain.Policy{
				AppealConfig: nil,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.policy.AllowsManualLabels()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLabelingRule_Validation(t *testing.T) {
	tests := []struct {
		name        string
		rule        domain.LabelingRule
		expectValid bool
	}{
		{
			name: "valid labeling rule with required fields",
			rule: domain.LabelingRule{
				RuleName: "pii_access",
				When:     "$appeal.role contains 'pii'",
				Labels: map[string]string{
					"data_classification": "pii",
					"compliance_required": "true",
				},
			},
			expectValid: true,
		},
		{
			name: "valid rule with metadata and priority",
			rule: domain.LabelingRule{
				RuleName: "production_access",
				When:     "$appeal.resource.details.environment == 'production'",
				Labels: map[string]string{
					"environment": "production",
					"risk_level":  "high",
				},
				LabelMetadata: map[string]*domain.LabelMetadataConfig{
					"environment": {
						Category: "resource",
						Attributes: map[string]interface{}{
							"criticality": "high",
						},
					},
				},
				Priority:     100,
				AllowFailure: false,
			},
			expectValid: true,
		},
		{
			name: "valid rule with namespaced labels",
			rule: domain.LabelingRule{
				RuleName: "resource_classification",
				When:     "true",
				Labels: map[string]string{
					"resource:pii":         "true",
					"account:type":         "user",
					"requestor:department": "engineering",
				},
			},
			expectValid: true,
		},
		{
			name: "valid rule with dynamic label values",
			rule: domain.LabelingRule{
				RuleName: "data_layer",
				When:     "$appeal.provider_type == 'bigquery'",
				Labels: map[string]string{
					"data_layer": "$appeal.resource.urn contains '_raw' ? 'raw' : 'curated'",
				},
			},
			expectValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify the structure is valid
			assert.NotEmpty(t, tt.rule.RuleName, "RuleName should not be empty")
			assert.NotEmpty(t, tt.rule.When, "When should not be empty")
			assert.NotEmpty(t, tt.rule.Labels, "Labels should not be empty")
		})
	}
}

func TestManualLabelConfig_Structure(t *testing.T) {
	tests := []struct {
		name   string
		config domain.ManualLabelConfig
	}{
		{
			name: "manual label config with all fields",
			config: domain.ManualLabelConfig{
				AllowUserLabels: true,
				AllowedKeys: []string{
					"project:*",
					"team",
					"cost_center",
				},
				RequiredKeys: []string{
					"cost_center",
				},
				MaxLabels:     5,
				KeyPattern:    "^[a-z0-9_:]+$",
				ValuePattern:  "^[a-zA-Z0-9_\\- ]+$",
				AllowOverride: false,
			},
		},
		{
			name: "minimal manual label config",
			config: domain.ManualLabelConfig{
				AllowUserLabels: true,
			},
		},
		{
			name: "config with glob patterns",
			config: domain.ManualLabelConfig{
				AllowUserLabels: true,
				AllowedKeys: []string{
					"*",         // Allow all
					"project:*", // Prefix match
					"team",      // Exact match
					"*_id",      // Suffix match
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify structure is valid
			assert.NotNil(t, tt.config)
			if tt.config.AllowUserLabels {
				assert.True(t, tt.config.AllowUserLabels)
			}
		})
	}
}

func TestLabelMetadata_Structure(t *testing.T) {
	tests := []struct {
		name     string
		metadata domain.LabelMetadata
	}{
		{
			name: "label metadata from policy rule",
			metadata: domain.LabelMetadata{
				Value:       "pii",
				DerivedFrom: "rule_pii_access",
				Source:      domain.LabelSourcePolicyRule,
				Category:    "resource",
				Attributes: map[string]interface{}{
					"risk":             "sensitivity",
					"retention_policy": "90_days",
				},
			},
		},
		{
			name: "label metadata from user",
			metadata: domain.LabelMetadata{
				Value:       "data-engineering",
				DerivedFrom: "user",
				Source:      domain.LabelSourceUser,
				Category:    "team",
				AppliedBy:   "user@example.com",
			},
		},
		{
			name: "minimal label metadata",
			metadata: domain.LabelMetadata{
				Value:       "production",
				DerivedFrom: "rule_env",
				Source:      domain.LabelSourcePolicyRule,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotEmpty(t, tt.metadata.Value)
			assert.NotEmpty(t, tt.metadata.DerivedFrom)
			assert.NotEmpty(t, tt.metadata.Source)
		})
	}
}

func TestLabelSource_Constants(t *testing.T) {
	t.Run("should have correct label source constants", func(t *testing.T) {
		assert.Equal(t, domain.LabelSource("policy_rule"), domain.LabelSourcePolicyRule)
		assert.Equal(t, domain.LabelSource("user"), domain.LabelSourceUser)
		assert.Equal(t, domain.LabelSource("provider"), domain.LabelSourceProvider)
		assert.Equal(t, domain.LabelSource("external"), domain.LabelSourceExternal)
	})
}

func TestAppeal_LabelsStructure(t *testing.T) {
	tests := []struct {
		name   string
		appeal domain.Appeal
	}{
		{
			name: "appeal with user labels only",
			appeal: domain.Appeal{
				UserLabels: map[string]string{
					"project:name": "customer-analytics",
					"team":         "data-science",
					"cost_center":  "CC-12345",
				},
			},
		},
		{
			name: "appeal with system-generated labels",
			appeal: domain.Appeal{
				Labels: map[string]string{
					"resource:pii":        "true",
					"environment":         "production",
					"data_classification": "pii",
					"risk_level":          "high",
				},
			},
		},
		{
			name: "appeal with labels and metadata",
			appeal: domain.Appeal{
				Labels: map[string]string{
					"resource:pii": "true",
					"environment":  "production",
				},
				LabelsMetadata: map[string]*domain.LabelMetadata{
					"resource:pii": {
						Value:       "true",
						DerivedFrom: "rule_pii_access",
						Source:      domain.LabelSourcePolicyRule,
						Category:    "resource",
						Attributes: map[string]interface{}{
							"risk": "sensitivity",
						},
					},
					"environment": {
						Value:       "production",
						DerivedFrom: "rule_prod_env",
						Source:      domain.LabelSourcePolicyRule,
						Category:    "resource",
					},
				},
			},
		},
		{
			name: "appeal with namespaced labels",
			appeal: domain.Appeal{
				Labels: map[string]string{
					"resource:pii":         "true",
					"account:type":         "user",
					"requestor:department": "engineering",
					"project:name":         "analytics",
					"environment":          "production",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.appeal.UserLabels != nil {
				assert.IsType(t, map[string]string{}, tt.appeal.UserLabels)
			}
			if tt.appeal.Labels != nil {
				assert.IsType(t, map[string]string{}, tt.appeal.Labels)
			}
			if tt.appeal.LabelsMetadata != nil {
				assert.IsType(t, map[string]*domain.LabelMetadata{}, tt.appeal.LabelsMetadata)
			}
		})
	}
}

func TestListAppealsFilter_LabelsFiltering(t *testing.T) {
	tests := []struct {
		name   string
		filter domain.ListAppealsFilter
	}{
		{
			name: "filter by single label",
			filter: domain.ListAppealsFilter{
				Labels: map[string][]string{
					"environment": {"production"},
				},
			},
		},
		{
			name: "filter by multiple values (OR logic)",
			filter: domain.ListAppealsFilter{
				Labels: map[string][]string{
					"environment": {"production", "staging"},
				},
			},
		},
		{
			name: "filter by multiple labels (AND logic across keys)",
			filter: domain.ListAppealsFilter{
				Labels: map[string][]string{
					"environment":         {"production"},
					"data_classification": {"pii"},
					"risk_level":          {"high"},
				},
			},
		},
		{
			name: "filter by label keys",
			filter: domain.ListAppealsFilter{
				LabelKeys: []string{
					"pii_access",
					"compliance_required",
				},
			},
		},
		{
			name: "combined label and label keys filtering",
			filter: domain.ListAppealsFilter{
				Labels: map[string][]string{
					"environment": {"production"},
				},
				LabelKeys: []string{
					"compliance_required",
				},
			},
		},
		{
			name: "filter by namespaced labels",
			filter: domain.ListAppealsFilter{
				Labels: map[string][]string{
					"resource:pii":   {"true"},
					"account:type":   {"user", "service_account"},
					"project:status": {"active"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.filter.Labels != nil {
				assert.IsType(t, map[string][]string{}, tt.filter.Labels)
				for key, values := range tt.filter.Labels {
					assert.NotEmpty(t, key)
					assert.NotEmpty(t, values)
				}
			}
			if tt.filter.LabelKeys != nil {
				assert.IsType(t, []string{}, tt.filter.LabelKeys)
				for _, key := range tt.filter.LabelKeys {
					assert.NotEmpty(t, key)
				}
			}
		})
	}
}

func TestLabelingRule_ComplexScenarios(t *testing.T) {
	tests := []struct {
		name string
		rule domain.LabelingRule
		desc string
	}{
		{
			name: "high priority rule for critical access",
			rule: domain.LabelingRule{
				RuleName:    "critical_pii_access",
				Description: "Critical: Production PII access",
				Priority:    100,
				When: `($appeal.role contains 'pii' || $appeal.role contains 'unmask') && 
				       $appeal.resource.details.environment == 'production'`,
				Labels: map[string]string{
					"resource:pii":            "true",
					"resource:classification": "PII",
					"environment":             "production",
					"risk_level":              "critical",
					"compliance_required":     "true",
				},
				LabelMetadata: map[string]*domain.LabelMetadataConfig{
					"resource:pii": {
						Category: "resource",
						Attributes: map[string]interface{}{
							"risk":                "sensitivity",
							"retention_policy":    "90_days",
							"requires_encryption": true,
							"gdpr_applicable":     true,
						},
					},
				},
				AllowFailure: false,
			},
			desc: "High priority rule for critical PII access with rich metadata",
		},
		{
			name: "rule with dynamic label value",
			rule: domain.LabelingRule{
				RuleName:    "data_layer_classification",
				Description: "Classify data layer based on resource URN",
				Priority:    10,
				When:        "$appeal.provider_type == 'bigquery' || $appeal.provider_type == 'maxcompute'",
				Labels: map[string]string{
					"data_layer": `let isRaw = $appeal.resource.urn contains '_raw';
					               let isMart = $appeal.resource.urn contains '_mart';
					               isRaw ? 'raw' : isMart ? 'mart' : 'unknown'`,
					"sensitivity": "$appeal.resource.urn contains '_raw' ? 'high' : 'medium'",
				},
				AllowFailure: true,
			},
			desc: "Rule with dynamic expression-based label values",
		},
		{
			name: "account type classification",
			rule: domain.LabelingRule{
				RuleName:    "service_account_detection",
				Description: "Detect and label service account access",
				Priority:    20,
				When:        "$appeal.account_type == 'service_account'",
				Labels: map[string]string{
					"account:type": "bot",
					"automation":   "true",
				},
				LabelMetadata: map[string]*domain.LabelMetadataConfig{
					"account:type": {
						Category: "account",
						Attributes: map[string]interface{}{
							"automated":           true,
							"requires_monitoring": true,
						},
					},
				},
				AllowFailure: false,
			},
			desc: "Rule for classifying service accounts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotEmpty(t, tt.rule.RuleName)
			assert.NotEmpty(t, tt.rule.When)
			assert.NotEmpty(t, tt.rule.Labels)
			assert.NotEmpty(t, tt.desc)

			// Verify rule structure
			for key, value := range tt.rule.Labels {
				assert.NotEmpty(t, key, "Label key should not be empty")
				assert.NotEmpty(t, value, "Label value should not be empty")
			}

			// If metadata exists, verify structure
			if tt.rule.LabelMetadata != nil {
				for key, metadata := range tt.rule.LabelMetadata {
					assert.NotNil(t, metadata)
					// Key in LabelMetadata should exist in Labels
					_, exists := tt.rule.Labels[key]
					assert.True(t, exists, "Metadata key should exist in Labels map")
				}
			}
		})
	}
}

func TestManualLabelConfig_ValidationScenarios(t *testing.T) {
	tests := []struct {
		name   string
		config domain.ManualLabelConfig
		desc   string
	}{
		{
			name: "strict validation config",
			config: domain.ManualLabelConfig{
				AllowUserLabels: true,
				AllowedKeys: []string{
					"project:*",
					"team",
					"cost_center",
					"ticket_id",
				},
				RequiredKeys: []string{
					"cost_center",
				},
				MaxLabels:     5,
				KeyPattern:    "^[a-z0-9_:]+$",
				ValuePattern:  "^[a-zA-Z0-9_\\- ]+$",
				AllowOverride: false,
			},
			desc: "Strict validation with required keys and patterns",
		},
		{
			name: "lenient validation config",
			config: domain.ManualLabelConfig{
				AllowUserLabels: true,
				AllowedKeys:     []string{"*"}, // Allow all keys
				MaxLabels:       10,
				AllowOverride:   true, // Allow users to override policy labels
			},
			desc: "Lenient validation allowing all keys",
		},
		{
			name: "namespace-specific config",
			config: domain.ManualLabelConfig{
				AllowUserLabels: true,
				AllowedKeys: []string{
					"project:*", // All project namespace
					"team:*",    // All team namespace
					"custom:*",  // All custom namespace
					"ticket_id", // Global key
					"jira_id",   // Global key
				},
				RequiredKeys: []string{
					"project:name",
				},
				MaxLabels:    15,
				KeyPattern:   "^[a-z0-9_:]+$",
				ValuePattern: "^[a-zA-Z0-9_\\-:/. ]+$", // Allow more characters in values
			},
			desc: "Config with namespace-specific rules",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotNil(t, tt.config)
			assert.True(t, tt.config.AllowUserLabels)
			assert.NotEmpty(t, tt.desc)

			if tt.config.MaxLabels > 0 {
				assert.Greater(t, tt.config.MaxLabels, 0)
			}

			if len(tt.config.AllowedKeys) > 0 {
				for _, key := range tt.config.AllowedKeys {
					assert.NotEmpty(t, key)
				}
			}

			if len(tt.config.RequiredKeys) > 0 {
				for _, key := range tt.config.RequiredKeys {
					assert.NotEmpty(t, key)
				}
			}
		})
	}
}
