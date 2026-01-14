package v1beta1_test

import (
	"testing"
	"time"

	"github.com/goto/guardian/api/handler/v1beta1"
	guardianv1beta1 "github.com/goto/guardian/api/proto/gotocompany/guardian/v1beta1"
	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestAdapter_FromCreateAppealProto_WithUserLabels(t *testing.T) {
	adapter := v1beta1.NewAdapter()
	authenticatedUser := "user@example.com"

	t.Run("should include user_labels from request", func(t *testing.T) {
		req := &guardianv1beta1.CreateAppealRequest{
			AccountId: "test-account",
			Resources: []*guardianv1beta1.CreateAppealRequest_Resource{
				{
					Id:   "resource-1",
					Role: "viewer",
				},
			},
			UserLabels: map[string]string{
				"cost_center": "CC-12345",
				"project":     "web-platform",
				"owner":       "team-alpha",
			},
		}

		appeals, err := adapter.FromCreateAppealProto(req, authenticatedUser)

		assert.NoError(t, err)
		assert.Len(t, appeals, 1)
		assert.Equal(t, "test-account", appeals[0].AccountID)
		assert.Equal(t, "resource-1", appeals[0].ResourceID)
		assert.Equal(t, "viewer", appeals[0].Role)
		assert.NotNil(t, appeals[0].UserLabels)
		assert.Equal(t, "CC-12345", appeals[0].UserLabels["cost_center"])
		assert.Equal(t, "web-platform", appeals[0].UserLabels["project"])
		assert.Equal(t, "team-alpha", appeals[0].UserLabels["owner"])
	})

	t.Run("should handle nil user_labels", func(t *testing.T) {
		req := &guardianv1beta1.CreateAppealRequest{
			AccountId: "test-account",
			Resources: []*guardianv1beta1.CreateAppealRequest_Resource{
				{
					Id:   "resource-1",
					Role: "viewer",
				},
			},
			UserLabels: nil,
		}

		appeals, err := adapter.FromCreateAppealProto(req, authenticatedUser)

		assert.NoError(t, err)
		assert.Len(t, appeals, 1)
		assert.Nil(t, appeals[0].UserLabels)
	})

	t.Run("should handle empty user_labels", func(t *testing.T) {
		req := &guardianv1beta1.CreateAppealRequest{
			AccountId: "test-account",
			Resources: []*guardianv1beta1.CreateAppealRequest_Resource{
				{
					Id:   "resource-1",
					Role: "viewer",
				},
			},
			UserLabels: map[string]string{},
		}

		appeals, err := adapter.FromCreateAppealProto(req, authenticatedUser)

		assert.NoError(t, err)
		assert.Len(t, appeals, 1)
		assert.NotNil(t, appeals[0].UserLabels)
		assert.Empty(t, appeals[0].UserLabels)
	})

	t.Run("should create multiple appeals with same user_labels", func(t *testing.T) {
		req := &guardianv1beta1.CreateAppealRequest{
			AccountId: "test-account",
			Resources: []*guardianv1beta1.CreateAppealRequest_Resource{
				{
					Id:   "resource-1",
					Role: "viewer",
				},
				{
					Id:   "resource-2",
					Role: "editor",
				},
			},
			UserLabels: map[string]string{
				"environment": "production",
			},
		}

		appeals, err := adapter.FromCreateAppealProto(req, authenticatedUser)

		assert.NoError(t, err)
		assert.Len(t, appeals, 2)
		assert.Equal(t, "production", appeals[0].UserLabels["environment"])
		assert.Equal(t, "production", appeals[1].UserLabels["environment"])
	})
}

func TestAdapter_ToLabelMetadataProto(t *testing.T) {
	// This is tested indirectly through ToAppealProto which uses toLabelMetadataProto internally
	t.Run("labels_metadata is included in ToAppealProto output", func(t *testing.T) {
		adapter := v1beta1.NewAdapter()
		timeNow := time.Now()

		appeal := &domain.Appeal{
			ID:         "appeal-123",
			ResourceID: "resource-1",
			Status:     "pending",
			AccountID:  "user@example.com",
			Role:       "viewer",
			Labels: map[string]string{
				"environment": "production",
				"cost_center": "CC-12345",
			},
			LabelsMetadata: map[string]*domain.LabelMetadata{
				"environment": {
					Value:       "production",
					Source:      domain.LabelSourcePolicyRule,
					DerivedFrom: "prod_rule",
					Category:    "deployment",
					AppliedBy:   "system",
					AppliedAt:   timeNow,
					Attributes: map[string]interface{}{
						"priority": 10,
					},
				},
				"cost_center": {
					Value:     "CC-12345",
					Source:    domain.LabelSourceUser,
					AppliedBy: "user@example.com",
					AppliedAt: timeNow,
				},
			},
			CreatedAt: timeNow,
			UpdatedAt: timeNow,
		}

		result, err := adapter.ToAppealProto(appeal)

		assert.NoError(t, err)
		assert.NotNil(t, result)

		// Verify labels are present
		assert.NotNil(t, result.Labels)
		assert.Equal(t, "production", result.Labels["environment"])
		assert.Equal(t, "CC-12345", result.Labels["cost_center"])

		// Verify labels_metadata is present and correctly converted
		assert.NotNil(t, result.LabelsMetadata)
		assert.Len(t, result.LabelsMetadata, 2)

		envMeta := result.LabelsMetadata["environment"]
		assert.NotNil(t, envMeta)
		assert.Equal(t, "production", envMeta.Value)
		assert.Equal(t, "policy_rule", envMeta.Source) // domain.LabelSourcePolicyRule converted to string
		assert.Equal(t, "prod_rule", envMeta.DerivedFrom)
		assert.Equal(t, "deployment", envMeta.Category)
		assert.Equal(t, "system", envMeta.AppliedBy)
		assert.NotNil(t, envMeta.AppliedAt)
		assert.NotNil(t, envMeta.Attributes)

		ccMeta := result.LabelsMetadata["cost_center"]
		assert.NotNil(t, ccMeta)
		assert.Equal(t, "CC-12345", ccMeta.Value)
		assert.Equal(t, "user", ccMeta.Source) // domain.LabelSourceUser converted to string
		assert.Equal(t, "user@example.com", ccMeta.AppliedBy)
	})

	t.Run("handles nil labels_metadata", func(t *testing.T) {
		adapter := v1beta1.NewAdapter()

		appeal := &domain.Appeal{
			ID:             "appeal-123",
			LabelsMetadata: nil,
		}

		result, err := adapter.ToAppealProto(appeal)

		assert.NoError(t, err)
		assert.Nil(t, result.LabelsMetadata)
	})

	t.Run("handles zero time in metadata", func(t *testing.T) {
		adapter := v1beta1.NewAdapter()

		appeal := &domain.Appeal{
			ID: "appeal-123",
			LabelsMetadata: map[string]*domain.LabelMetadata{
				"label1": {
					Value:     "value1",
					Source:    domain.LabelSourcePolicyRule,
					AppliedAt: time.Time{}, // Zero time should result in nil
				},
			},
		}

		result, err := adapter.ToAppealProto(appeal)

		assert.NoError(t, err)
		assert.NotNil(t, result.LabelsMetadata)
		// Zero time should not be included
		assert.Nil(t, result.LabelsMetadata["label1"].AppliedAt)
	})
}

func TestAdapter_FromLabelFiltersProto(t *testing.T) {
	adapter := v1beta1.NewAdapter()

	t.Run("should convert label filters with single values", func(t *testing.T) {
		protoFilters := map[string]*guardianv1beta1.LabelValues{
			"environment": {
				Values: []string{"production"},
			},
			"tier": {
				Values: []string{"premium"},
			},
		}

		result := adapter.FromLabelFiltersProto(protoFilters)

		assert.NotNil(t, result)
		assert.Len(t, result, 2)
		assert.Equal(t, []string{"production"}, result["environment"])
		assert.Equal(t, []string{"premium"}, result["tier"])
	})

	t.Run("should convert label filters with multiple values (OR condition)", func(t *testing.T) {
		protoFilters := map[string]*guardianv1beta1.LabelValues{
			"environment": {
				Values: []string{"production", "staging", "development"},
			},
		}

		result := adapter.FromLabelFiltersProto(protoFilters)

		assert.NotNil(t, result)
		assert.Len(t, result, 1)
		assert.Equal(t, []string{"production", "staging", "development"}, result["environment"])
	})

	t.Run("should handle nil label filters", func(t *testing.T) {
		result := adapter.FromLabelFiltersProto(nil)
		assert.Nil(t, result)
	})

	t.Run("should handle empty label filters", func(t *testing.T) {
		result := adapter.FromLabelFiltersProto(map[string]*guardianv1beta1.LabelValues{})
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("should skip nil label values", func(t *testing.T) {
		protoFilters := map[string]*guardianv1beta1.LabelValues{
			"environment": {
				Values: []string{"production"},
			},
			"tier": nil,
		}

		result := adapter.FromLabelFiltersProto(protoFilters)

		assert.NotNil(t, result)
		assert.Len(t, result, 1)
		assert.Contains(t, result, "environment")
		assert.NotContains(t, result, "tier")
	})

	t.Run("should skip empty values array", func(t *testing.T) {
		protoFilters := map[string]*guardianv1beta1.LabelValues{
			"environment": {
				Values: []string{"production"},
			},
			"tier": {
				Values: nil,
			},
		}

		result := adapter.FromLabelFiltersProto(protoFilters)

		assert.NotNil(t, result)
		assert.Len(t, result, 1)
		assert.Contains(t, result, "environment")
		assert.NotContains(t, result, "tier")
	})
}

func TestAdapter_ToAppealProto_WithLabelsMetadata(t *testing.T) {
	adapter := v1beta1.NewAdapter()
	timeNow := time.Now()

	t.Run("should include labels and labels_metadata in response", func(t *testing.T) {
		appeal := &domain.Appeal{
			ID:         "appeal-123",
			ResourceID: "resource-1",
			Status:     "pending",
			AccountID:  "user@example.com",
			Role:       "viewer",
			Labels: map[string]string{
				"environment": "production",
				"cost_center": "CC-12345",
			},
			LabelsMetadata: map[string]*domain.LabelMetadata{
				"environment": {
					Value:       "production",
					Source:      domain.LabelSourcePolicyRule,
					DerivedFrom: "prod_rule",
					AppliedAt:   timeNow,
				},
				"cost_center": {
					Value:     "CC-12345",
					Source:    domain.LabelSourceUser,
					AppliedBy: "user@example.com",
					AppliedAt: timeNow,
				},
			},
			CreatedAt: timeNow,
			UpdatedAt: timeNow,
		}

		result, err := adapter.ToAppealProto(appeal)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "appeal-123", result.Id)
		assert.NotNil(t, result.Labels)
		assert.Equal(t, "production", result.Labels["environment"])
		assert.Equal(t, "CC-12345", result.Labels["cost_center"])

		assert.NotNil(t, result.LabelsMetadata)
		assert.Len(t, result.LabelsMetadata, 2)
		assert.Equal(t, "production", result.LabelsMetadata["environment"].Value)
		assert.Equal(t, "policy_rule", result.LabelsMetadata["environment"].Source)
		assert.Equal(t, "CC-12345", result.LabelsMetadata["cost_center"].Value)
		assert.Equal(t, "user", result.LabelsMetadata["cost_center"].Source)
	})

	t.Run("should handle nil labels and labels_metadata", func(t *testing.T) {
		appeal := &domain.Appeal{
			ID:             "appeal-123",
			ResourceID:     "resource-1",
			Status:         "pending",
			Labels:         nil,
			LabelsMetadata: nil,
		}

		result, err := adapter.ToAppealProto(appeal)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Nil(t, result.Labels)
		assert.Nil(t, result.LabelsMetadata)
	})

	t.Run("should handle empty labels and labels_metadata", func(t *testing.T) {
		appeal := &domain.Appeal{
			ID:             "appeal-123",
			ResourceID:     "resource-1",
			Status:         "pending",
			Labels:         map[string]string{},
			LabelsMetadata: map[string]*domain.LabelMetadata{},
		}

		result, err := adapter.ToAppealProto(appeal)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotNil(t, result.Labels)
		assert.Empty(t, result.Labels)
		assert.NotNil(t, result.LabelsMetadata)
		assert.Empty(t, result.LabelsMetadata)
	})
}

func TestAdapter_FromPolicyProto_WithLabelingConfig(t *testing.T) {
	adapter := v1beta1.NewAdapter()

	t.Run("should convert labeling_rules from proto to domain", func(t *testing.T) {
		policyProto := &guardianv1beta1.Policy{
			Id:          "test-policy",
			Version:     1,
			Description: "Test policy with labeling rules",
			Steps: []*guardianv1beta1.Policy_ApprovalStep{
				{
					Name:      "auto_approval",
					Strategy:  "auto",
					ApproveIf: "true",
				},
			},
			Appeal: &guardianv1beta1.PolicyAppealConfig{
				LabelingRules: []*guardianv1beta1.LabelingRule{
					{
						RuleName:    "environment_rule",
						Description: "Apply environment labels",
						When:        "true",
						Labels: map[string]string{
							"environment": "production",
							"tier":        "critical",
						},
						Priority:     10,
						AllowFailure: false,
					},
					{
						RuleName:    "team_rule",
						Description: "Apply team labels",
						When:        "$appeal.resource.type == 'dataset'",
						Labels: map[string]string{
							"team": "data-engineering",
						},
						Priority:     5,
						AllowFailure: true,
					},
				},
			},
		}

		result := adapter.FromPolicyProto(policyProto)

		assert.NotNil(t, result)
		assert.Equal(t, "test-policy", result.ID)
		assert.NotNil(t, result.AppealConfig)
		assert.NotNil(t, result.AppealConfig.LabelingRules)
		assert.Len(t, result.AppealConfig.LabelingRules, 2)

		rule1 := result.AppealConfig.LabelingRules[0]
		assert.Equal(t, "environment_rule", rule1.RuleName)
		assert.Equal(t, "Apply environment labels", rule1.Description)
		assert.Equal(t, "true", rule1.When)
		assert.Equal(t, "production", rule1.Labels["environment"])
		assert.Equal(t, "critical", rule1.Labels["tier"])
		assert.Equal(t, 10, rule1.Priority)
		assert.False(t, rule1.AllowFailure)

		rule2 := result.AppealConfig.LabelingRules[1]
		assert.Equal(t, "team_rule", rule2.RuleName)
		assert.Equal(t, "data-engineering", rule2.Labels["team"])
		assert.Equal(t, 5, rule2.Priority)
		assert.True(t, rule2.AllowFailure)
	})

	t.Run("should convert manual_label_config from proto to domain", func(t *testing.T) {
		policyProto := &guardianv1beta1.Policy{
			Id:      "test-policy",
			Version: 1,
			Steps: []*guardianv1beta1.Policy_ApprovalStep{
				{
					Name:      "auto_approval",
					Strategy:  "auto",
					ApproveIf: "true",
				},
			},
			Appeal: &guardianv1beta1.PolicyAppealConfig{
				ManualLabelConfig: &guardianv1beta1.ManualLabelConfig{
					AllowUserLabels: true,
					AllowedKeys:     []string{"project", "cost_center", "owner"},
					RequiredKeys:    []string{"cost_center"},
					MaxLabels:       10,
					KeyPattern:      "^[a-z_]+$",
					ValuePattern:    "^[a-zA-Z0-9-]+$",
					AllowOverride:   false,
				},
			},
		}

		result := adapter.FromPolicyProto(policyProto)

		assert.NotNil(t, result)
		assert.NotNil(t, result.AppealConfig)
		assert.NotNil(t, result.AppealConfig.ManualLabelConfig)

		mlc := result.AppealConfig.ManualLabelConfig
		assert.True(t, mlc.AllowUserLabels)
		assert.Equal(t, []string{"project", "cost_center", "owner"}, mlc.AllowedKeys)
		assert.Equal(t, []string{"cost_center"}, mlc.RequiredKeys)
		assert.Equal(t, 10, mlc.MaxLabels)
		assert.Equal(t, "^[a-z_]+$", mlc.KeyPattern)
		assert.Equal(t, "^[a-zA-Z0-9-]+$", mlc.ValuePattern)
		assert.False(t, mlc.AllowOverride)
	})

	t.Run("should convert label_metadata in labeling_rules", func(t *testing.T) {
		attrs, err := structpb.NewStruct(map[string]interface{}{
			"priority": 10.0,
			"critical": true,
		})
		assert.NoError(t, err)

		policyProto := &guardianv1beta1.Policy{
			Id:      "test-policy",
			Version: 1,
			Steps: []*guardianv1beta1.Policy_ApprovalStep{
				{
					Name:      "auto_approval",
					Strategy:  "auto",
					ApproveIf: "true",
				},
			},
			Appeal: &guardianv1beta1.PolicyAppealConfig{
				LabelingRules: []*guardianv1beta1.LabelingRule{
					{
						RuleName: "env_rule",
						When:     "true",
						Labels: map[string]string{
							"environment": "production",
						},
						LabelMetadata: map[string]*guardianv1beta1.LabelMetadataConfig{
							"environment": {
								Category:   "deployment",
								Attributes: attrs,
							},
						},
					},
				},
			},
		}

		result := adapter.FromPolicyProto(policyProto)

		assert.NotNil(t, result)
		assert.NotNil(t, result.AppealConfig.LabelingRules)
		assert.Len(t, result.AppealConfig.LabelingRules, 1)

		rule := result.AppealConfig.LabelingRules[0]
		assert.NotNil(t, rule.LabelMetadata)
		assert.Contains(t, rule.LabelMetadata, "environment")

		metadata := rule.LabelMetadata["environment"]
		assert.Equal(t, "deployment", metadata.Category)
		assert.NotNil(t, metadata.Attributes)
	})

	t.Run("should handle nil labeling_rules", func(t *testing.T) {
		policyProto := &guardianv1beta1.Policy{
			Id:      "test-policy",
			Version: 1,
			Steps: []*guardianv1beta1.Policy_ApprovalStep{
				{
					Name:      "auto_approval",
					Strategy:  "auto",
					ApproveIf: "true",
				},
			},
			Appeal: &guardianv1beta1.PolicyAppealConfig{
				LabelingRules: nil,
			},
		}

		result := adapter.FromPolicyProto(policyProto)

		assert.NotNil(t, result)
		assert.NotNil(t, result.AppealConfig)
		assert.Nil(t, result.AppealConfig.LabelingRules)
	})

	t.Run("should handle nil manual_label_config", func(t *testing.T) {
		policyProto := &guardianv1beta1.Policy{
			Id:      "test-policy",
			Version: 1,
			Steps: []*guardianv1beta1.Policy_ApprovalStep{
				{
					Name:      "auto_approval",
					Strategy:  "auto",
					ApproveIf: "true",
				},
			},
			Appeal: &guardianv1beta1.PolicyAppealConfig{
				ManualLabelConfig: nil,
			},
		}

		result := adapter.FromPolicyProto(policyProto)

		assert.NotNil(t, result)
		assert.NotNil(t, result.AppealConfig)
		assert.Nil(t, result.AppealConfig.ManualLabelConfig)
	})

	t.Run("should handle nil appeal config", func(t *testing.T) {
		policyProto := &guardianv1beta1.Policy{
			Id:      "test-policy",
			Version: 1,
			Steps: []*guardianv1beta1.Policy_ApprovalStep{
				{
					Name:      "auto_approval",
					Strategy:  "auto",
					ApproveIf: "true",
				},
			},
			Appeal: nil,
		}

		result := adapter.FromPolicyProto(policyProto)

		assert.NotNil(t, result)
		assert.Nil(t, result.AppealConfig)
	})
}

func TestAdapter_ToPolicyProto_WithLabelingConfig(t *testing.T) {
	adapter := v1beta1.NewAdapter()

	t.Run("should convert labeling_rules from domain to proto", func(t *testing.T) {
		policy := &domain.Policy{
			ID:          "test-policy",
			Version:     1,
			Description: "Test policy with labeling rules",
			Steps: []*domain.Step{
				{
					Name:      "auto_approval",
					Strategy:  domain.ApprovalStepStrategyAuto,
					ApproveIf: "true",
				},
			},
			AppealConfig: &domain.PolicyAppealConfig{
				LabelingRules: []domain.LabelingRule{
					{
						RuleName:    "environment_rule",
						Description: "Apply environment labels",
						When:        "true",
						Labels: map[string]string{
							"environment": "production",
							"tier":        "critical",
						},
						Priority:     10,
						AllowFailure: false,
					},
					{
						RuleName:    "team_rule",
						Description: "Apply team labels",
						When:        "$appeal.resource.type == 'dataset'",
						Labels: map[string]string{
							"team": "data-engineering",
						},
						Priority:     5,
						AllowFailure: true,
					},
				},
			},
		}

		result, err := adapter.ToPolicyProto(policy)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "test-policy", result.Id)
		assert.NotNil(t, result.Appeal)
		assert.NotNil(t, result.Appeal.LabelingRules)
		assert.Len(t, result.Appeal.LabelingRules, 2)

		rule1 := result.Appeal.LabelingRules[0]
		assert.Equal(t, "environment_rule", rule1.RuleName)
		assert.Equal(t, "Apply environment labels", rule1.Description)
		assert.Equal(t, "true", rule1.When)
		assert.Equal(t, "production", rule1.Labels["environment"])
		assert.Equal(t, "critical", rule1.Labels["tier"])
		assert.Equal(t, int32(10), rule1.Priority)
		assert.False(t, rule1.AllowFailure)

		rule2 := result.Appeal.LabelingRules[1]
		assert.Equal(t, "team_rule", rule2.RuleName)
		assert.Equal(t, "data-engineering", rule2.Labels["team"])
		assert.Equal(t, int32(5), rule2.Priority)
		assert.True(t, rule2.AllowFailure)
	})

	t.Run("should convert manual_label_config from domain to proto", func(t *testing.T) {
		policy := &domain.Policy{
			ID:      "test-policy",
			Version: 1,
			Steps: []*domain.Step{
				{
					Name:      "auto_approval",
					Strategy:  domain.ApprovalStepStrategyAuto,
					ApproveIf: "true",
				},
			},
			AppealConfig: &domain.PolicyAppealConfig{
				ManualLabelConfig: &domain.ManualLabelConfig{
					AllowUserLabels: true,
					AllowedKeys:     []string{"project", "cost_center", "owner"},
					RequiredKeys:    []string{"cost_center"},
					MaxLabels:       10,
					KeyPattern:      "^[a-z_]+$",
					ValuePattern:    "^[a-zA-Z0-9-]+$",
					AllowOverride:   false,
				},
			},
		}

		result, err := adapter.ToPolicyProto(policy)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotNil(t, result.Appeal)
		assert.NotNil(t, result.Appeal.ManualLabelConfig)

		mlc := result.Appeal.ManualLabelConfig
		assert.True(t, mlc.AllowUserLabels)
		assert.Equal(t, []string{"project", "cost_center", "owner"}, mlc.AllowedKeys)
		assert.Equal(t, []string{"cost_center"}, mlc.RequiredKeys)
		assert.Equal(t, int32(10), mlc.MaxLabels)
		assert.Equal(t, "^[a-z_]+$", mlc.KeyPattern)
		assert.Equal(t, "^[a-zA-Z0-9-]+$", mlc.ValuePattern)
		assert.False(t, mlc.AllowOverride)
	})

	t.Run("should convert label_metadata in labeling_rules", func(t *testing.T) {
		policy := &domain.Policy{
			ID:      "test-policy",
			Version: 1,
			Steps: []*domain.Step{
				{
					Name:      "auto_approval",
					Strategy:  domain.ApprovalStepStrategyAuto,
					ApproveIf: "true",
				},
			},
			AppealConfig: &domain.PolicyAppealConfig{
				LabelingRules: []domain.LabelingRule{
					{
						RuleName: "env_rule",
						When:     "true",
						Labels: map[string]string{
							"environment": "production",
						},
						LabelMetadata: map[string]*domain.LabelMetadataConfig{
							"environment": {
								Category: "deployment",
								Attributes: map[string]interface{}{
									"priority": 10,
									"critical": true,
								},
							},
						},
					},
				},
			},
		}

		result, err := adapter.ToPolicyProto(policy)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotNil(t, result.Appeal.LabelingRules)
		assert.Len(t, result.Appeal.LabelingRules, 1)

		rule := result.Appeal.LabelingRules[0]
		assert.NotNil(t, rule.LabelMetadata)
		assert.Contains(t, rule.LabelMetadata, "environment")

		metadata := rule.LabelMetadata["environment"]
		assert.Equal(t, "deployment", metadata.Category)
		assert.NotNil(t, metadata.Attributes)
		assert.NotNil(t, metadata.Attributes.AsMap())
	})

	t.Run("should handle nil labeling_rules", func(t *testing.T) {
		policy := &domain.Policy{
			ID:      "test-policy",
			Version: 1,
			Steps: []*domain.Step{
				{
					Name:      "auto_approval",
					Strategy:  domain.ApprovalStepStrategyAuto,
					ApproveIf: "true",
				},
			},
			AppealConfig: &domain.PolicyAppealConfig{
				LabelingRules: nil,
			},
		}

		result, err := adapter.ToPolicyProto(policy)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotNil(t, result.Appeal)
		assert.Nil(t, result.Appeal.LabelingRules)
	})

	t.Run("should handle nil manual_label_config", func(t *testing.T) {
		policy := &domain.Policy{
			ID:      "test-policy",
			Version: 1,
			Steps: []*domain.Step{
				{
					Name:      "auto_approval",
					Strategy:  domain.ApprovalStepStrategyAuto,
					ApproveIf: "true",
				},
			},
			AppealConfig: &domain.PolicyAppealConfig{
				ManualLabelConfig: nil,
			},
		}

		result, err := adapter.ToPolicyProto(policy)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotNil(t, result.Appeal)
		assert.Nil(t, result.Appeal.ManualLabelConfig)
	})

	t.Run("should handle empty labeling_rules", func(t *testing.T) {
		policy := &domain.Policy{
			ID:      "test-policy",
			Version: 1,
			Steps: []*domain.Step{
				{
					Name:      "auto_approval",
					Strategy:  domain.ApprovalStepStrategyAuto,
					ApproveIf: "true",
				},
			},
			AppealConfig: &domain.PolicyAppealConfig{
				LabelingRules: []domain.LabelingRule{},
			},
		}

		result, err := adapter.ToPolicyProto(policy)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotNil(t, result.Appeal)
		// Empty slice results in nil for proto repeated fields
		assert.Nil(t, result.Appeal.LabelingRules)
	})

	t.Run("should handle nil appeal config", func(t *testing.T) {
		policy := &domain.Policy{
			ID:      "test-policy",
			Version: 1,
			Steps: []*domain.Step{
				{
					Name:      "auto_approval",
					Strategy:  domain.ApprovalStepStrategyAuto,
					ApproveIf: "true",
				},
			},
			AppealConfig: nil,
		}

		result, err := adapter.ToPolicyProto(policy)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Nil(t, result.Appeal)
	})

	t.Run("should roundtrip labeling config correctly", func(t *testing.T) {
		originalPolicy := &domain.Policy{
			ID:      "test-policy",
			Version: 1,
			Steps: []*domain.Step{
				{
					Name:      "auto_approval",
					Strategy:  domain.ApprovalStepStrategyAuto,
					ApproveIf: "true",
				},
			},
			AppealConfig: &domain.PolicyAppealConfig{
				LabelingRules: []domain.LabelingRule{
					{
						RuleName: "test_rule",
						When:     "true",
						Labels: map[string]string{
							"environment": "production",
						},
						Priority: 10,
					},
				},
				ManualLabelConfig: &domain.ManualLabelConfig{
					AllowUserLabels: true,
					MaxLabels:       5,
				},
			},
		}

		protoPolicy, err := adapter.ToPolicyProto(originalPolicy)
		assert.NoError(t, err)

		roundtrippedPolicy := adapter.FromPolicyProto(protoPolicy)

		assert.Equal(t, originalPolicy.ID, roundtrippedPolicy.ID)
		assert.NotNil(t, roundtrippedPolicy.AppealConfig)
		assert.Len(t, roundtrippedPolicy.AppealConfig.LabelingRules, 1)
		assert.Equal(t, "test_rule", roundtrippedPolicy.AppealConfig.LabelingRules[0].RuleName)
		assert.Equal(t, "production", roundtrippedPolicy.AppealConfig.LabelingRules[0].Labels["environment"])
		assert.NotNil(t, roundtrippedPolicy.AppealConfig.ManualLabelConfig)
		assert.True(t, roundtrippedPolicy.AppealConfig.ManualLabelConfig.AllowUserLabels)
		assert.Equal(t, 5, roundtrippedPolicy.AppealConfig.ManualLabelConfig.MaxLabels)
	})
}
