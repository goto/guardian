package v1beta1_test

import (
	"testing"
	"time"

	"github.com/goto/guardian/api/handler/v1beta1"
	guardianv1beta1 "github.com/goto/guardian/api/proto/gotocompany/guardian/v1beta1"
	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/assert"
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
