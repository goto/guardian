package postgres

import (
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/assert"
)

func Test_generateSummaryResultCount(t *testing.T) {
	t.Run("should return nil for nil input", func(t *testing.T) {
		result := generateSummaryResultCount(nil)
		assert.Nil(t, result)
	})

	t.Run("should compute groups count from individual group counts", func(t *testing.T) {
		input := &domain.SummaryResult{
			SummaryGroups: []*domain.SummaryGroup{
				{Count: 3},
				{Count: 7},
			},
		}

		result := generateSummaryResultCount(input)

		assert.NotNil(t, result)
		assert.Equal(t, int32(10), result.GroupsCount)
	})

	t.Run("should compute uniques count from individual unique counts", func(t *testing.T) {
		input := &domain.SummaryResult{
			SummaryUniques: []*domain.SummaryUnique{
				{Count: 4},
				{Count: 6},
			},
		}

		result := generateSummaryResultCount(input)

		assert.NotNil(t, result)
		assert.Equal(t, int32(10), result.UniquesCount)
	})

	t.Run("should compute V1 labels count from slice length", func(t *testing.T) {
		input := &domain.SummaryResult{
			SummaryLabels: []*domain.SummaryLabel{
				{Key: "env"},
				{Key: "team"},
				{Key: "region"},
			},
		}

		result := generateSummaryResultCount(input)

		assert.NotNil(t, result)
		assert.Equal(t, int32(3), result.LabelsCount)
		assert.Equal(t, int32(0), result.LabelsV2Count)
	})

	t.Run("should compute V2 labels count from slice length", func(t *testing.T) {
		input := &domain.SummaryResult{
			SummaryLabelsV2: []*domain.SummaryLabelV2{
				{Key: "env", Values: []string{"prod", "staging"}, Count: 2},
				{Key: "team", Values: []string{"data", "backend"}, Count: 2},
			},
		}

		result := generateSummaryResultCount(input)

		assert.NotNil(t, result)
		assert.Equal(t, int32(0), result.LabelsCount)
		assert.Equal(t, int32(2), result.LabelsV2Count)
		assert.Equal(t, input.SummaryLabelsV2, result.SummaryLabelsV2)
	})

	t.Run("should compute both V1 and V2 labels counts independently", func(t *testing.T) {
		input := &domain.SummaryResult{
			SummaryLabels: []*domain.SummaryLabel{
				{Key: "env"},
			},
			SummaryLabelsV2: []*domain.SummaryLabelV2{
				{Key: "env", Values: []string{"prod", "staging"}, Count: 2},
				{Key: "team", Values: []string{"data"}, Count: 1},
			},
		}

		result := generateSummaryResultCount(input)

		assert.NotNil(t, result)
		assert.Equal(t, int32(1), result.LabelsCount)
		assert.Equal(t, int32(2), result.LabelsV2Count)
	})

	t.Run("should preserve all fields in the returned result", func(t *testing.T) {
		groups := []*domain.SummaryGroup{{Count: 5}}
		uniques := []*domain.SummaryUnique{{Count: 3}}
		labelsV1 := []*domain.SummaryLabel{{Key: "env"}}
		labelsV2 := []*domain.SummaryLabelV2{{Key: "env", Values: []string{"prod"}, Count: 1}}

		input := &domain.SummaryResult{
			SummaryGroups:   groups,
			SummaryUniques:  uniques,
			SummaryLabels:   labelsV1,
			SummaryLabelsV2: labelsV2,
		}

		result := generateSummaryResultCount(input)

		assert.Equal(t, groups, result.SummaryGroups)
		assert.Equal(t, uniques, result.SummaryUniques)
		assert.Equal(t, labelsV1, result.SummaryLabels)
		assert.Equal(t, labelsV2, result.SummaryLabelsV2)
		assert.Equal(t, int32(5), result.GroupsCount)
		assert.Equal(t, int32(3), result.UniquesCount)
		assert.Equal(t, int32(1), result.LabelsCount)
		assert.Equal(t, int32(1), result.LabelsV2Count)
	})
}
