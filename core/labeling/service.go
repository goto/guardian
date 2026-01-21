package labeling

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/goto/guardian/pkg/log"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/evaluator"
)

type Service interface {
	// ApplyLabels applies policy-based labeling rules to an appeal
	ApplyLabels(ctx context.Context, appeal *domain.Appeal, resource *domain.Resource, policy *domain.Policy) (map[string]*domain.LabelMetadata, error)

	// ValidateManualLabels validates user-provided labels against policy configuration
	ValidateManualLabels(ctx context.Context, userLabels map[string]string, config *domain.ManualLabelConfig) error

	// MergeLabels combines policy-based and manual labels with conflict resolution
	MergeLabels(policyLabels, manualLabels map[string]*domain.LabelMetadata, allowOverride bool) map[string]*domain.LabelMetadata
}

type ServiceDeps struct {
	Logger log.Logger
}

type service struct {
	Logger log.Logger
	// Dependencies can be added here if needed (e.g., logger, evaluator, etc.)
}

func NewService(deps ServiceDeps) Service {
	return &service{
		Logger: deps.Logger,
	}
}

// ApplyLabels applies all matching labeling rules from the policy to an appeal
func (s *service) ApplyLabels(ctx context.Context, appeal *domain.Appeal, resource *domain.Resource, policy *domain.Policy) (map[string]*domain.LabelMetadata, error) {
	if !policy.HasLabelingRules() {
		return make(map[string]*domain.LabelMetadata), nil
	}

	// Sort rules by priority (higher priority first)
	rules := make([]domain.LabelingRule, len(policy.AppealConfig.LabelingRules))
	copy(rules, policy.AppealConfig.LabelingRules)
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority > rules[j].Priority
	})

	labelsMetadata := make(map[string]*domain.LabelMetadata)
	now := time.Now()

	appealMap, err := appeal.ToMap()
	if err != nil {
		return nil, fmt.Errorf("failed to convert appeal to map: %w", err)
	}

	evalContext := map[string]any{
		"appeal": appealMap,
	}

	for _, rule := range rules {
		// Evaluate the 'when' condition
		shouldApply, err := s.evaluateCondition(rule.When, evalContext)
		if err != nil {
			if rule.AllowFailure {
				// Skip this rule on error if AllowFailure is true
				continue
			}
			return nil, fmt.Errorf("failed to evaluate rule '%s': %w", rule.RuleName, err)
		}

		if !shouldApply {
			continue
		}

		// Apply labels from this rule
		for key, value := range rule.Labels {
			// Evaluate dynamic label values (expressions)
			evaluatedValue, err := s.evaluateLabelValue(ctx, value, evalContext)
			if err != nil {
				if rule.AllowFailure {
					continue
				}
				return nil, fmt.Errorf("failed to evaluate label value for key '%s' in rule '%s': %w", key, rule.RuleName, err)
			}

			// Check if label already exists (lower priority rule might have set it)
			if existing, exists := labelsMetadata[key]; exists {
				// Skip if existing label has higher or equal priority
				if existing.DerivedFrom != "" && existing.DerivedFrom != rule.RuleName {
					// This means another rule set this label, check priority
					continue
				}
			}

			// Create label metadata
			metadata := &domain.LabelMetadata{
				Value:       evaluatedValue,
				DerivedFrom: rule.RuleName,
				Source:      domain.LabelSourcePolicyRule,
				AppliedAt:   now,
			}

			// Apply label-specific metadata config if available
			if rule.LabelMetadata != nil {
				if metaConfig, ok := rule.LabelMetadata[key]; ok {
					metadata.Category = metaConfig.Category
					metadata.Attributes = metaConfig.Attributes
				}
			}

			labelsMetadata[key] = metadata
		}
	}

	return labelsMetadata, nil
}

// ValidateManualLabels validates user-provided labels against policy configuration
func (s *service) ValidateManualLabels(ctx context.Context, userLabels map[string]string, config *domain.ManualLabelConfig) error {
	if config == nil {
		if len(userLabels) > 0 {
			return fmt.Errorf("manual labels are not allowed (no configuration provided)")
		}
		return nil
	}

	// Check if manual labels are allowed
	if !config.AllowUserLabels {
		if len(userLabels) > 0 {
			return fmt.Errorf("manual labels are not allowed by policy")
		}
		return nil
	}

	// Check max labels limit
	if config.MaxLabels > 0 && len(userLabels) > config.MaxLabels {
		return fmt.Errorf("number of labels (%d) exceeds maximum allowed (%d)", len(userLabels), config.MaxLabels)
	}

	// Build allowed keys set for quick lookup
	allowedKeysSet := make(map[string]bool)
	if len(config.AllowedKeys) > 0 {
		for _, key := range config.AllowedKeys {
			allowedKeysSet[key] = true
		}
	}

	// Build required keys set
	requiredKeysSet := make(map[string]bool)
	if len(config.RequiredKeys) > 0 {
		for _, key := range config.RequiredKeys {
			requiredKeysSet[key] = true
		}
	}

	// Validate each user-provided label
	for key, value := range userLabels {
		// Check if key is allowed
		if len(allowedKeysSet) > 0 && !allowedKeysSet[key] {
			return fmt.Errorf("label key '%s' is not in the allowed keys list", key)
		}

		// Validate against key pattern if configured
		if config.KeyPattern != "" {
			if err := s.validatePattern("key", key, config.KeyPattern); err != nil {
				return err
			}
		}

		// Validate against value pattern if configured
		if config.ValuePattern != "" {
			if err := s.validatePattern("value", value, config.ValuePattern); err != nil {
				return err
			}
		}

		// Remove from required set if present
		delete(requiredKeysSet, key)
	}

	// Check if all required keys are present
	if len(requiredKeysSet) > 0 {
		missingKeys := make([]string, 0, len(requiredKeysSet))
		for key := range requiredKeysSet {
			missingKeys = append(missingKeys, key)
		}
		return fmt.Errorf("required label keys missing: %v", missingKeys)
	}

	return nil
}

// MergeLabels combines policy-based and manual labels
func (s *service) MergeLabels(policyLabels, manualLabels map[string]*domain.LabelMetadata, allowOverride bool) map[string]*domain.LabelMetadata {
	merged := make(map[string]*domain.LabelMetadata)

	// Start with policy labels
	for key, value := range policyLabels {
		merged[key] = value
	}

	// Add or override with manual labels
	for key, value := range manualLabels {
		if _, exists := merged[key]; exists {
			// Label exists from policy
			if allowOverride {
				// Manual label overrides policy label
				merged[key] = value
			}
		} else {
			// New label from user
			merged[key] = value
		}
	}

	return merged
}

// evaluateCondition evaluates a boolean expression
func (s *service) evaluateCondition(condition string, context map[string]interface{}) (bool, error) {
	if condition == "" {
		return true, nil
	}

	expr := evaluator.Expression(condition)
	result, err := expr.EvaluateWithVars(context)
	if err != nil {
		return false, fmt.Errorf("failed to evaluate expression: %w", err)
	}

	boolResult, ok := result.(bool)
	if !ok {
		return false, fmt.Errorf("expression did not return boolean value")
	}

	return boolResult, nil
}

// evaluateLabelValue evaluates a label value which may be a static string or an expression
func (s *service) evaluateLabelValue(ctx context.Context, value string, context map[string]interface{}) (string, error) {
	// Check if the value contains expression markers (similar to AppealMetadataSource.evaluateValue)
	// Only evaluate if it contains variable references
	if !strings.Contains(value, "$appeal") && !strings.Contains(value, "$resource") && !strings.Contains(value, "$policy") {
		// Static string, return as-is
		return value, nil
	}

	// Try to evaluate as expression
	expr := evaluator.Expression(value)
	result, err := expr.EvaluateWithVars(context)
	if err != nil {
		// If evaluation fails, return error
		s.Logger.Error(ctx, "Label value evaluation failed", "value", value, "context", context, "error", err)
		return "", fmt.Errorf("failed to evaluate expression: %w", err)
	}

	// Convert result to string
	switch v := result.(type) {
	case string:
		return v, nil
	case int, int8, int16, int32, int64:
		return fmt.Sprintf("%d", v), nil
	case float32, float64:
		return fmt.Sprintf("%f", v), nil
	case bool:
		return fmt.Sprintf("%t", v), nil
	default:
		return fmt.Sprintf("%v", v), nil
	}
}

// validatePattern validates a value against a regex pattern
func (s *service) validatePattern(fieldType, value, pattern string) error {
	matched, err := regexp.MatchString(pattern, value)
	if err != nil {
		return fmt.Errorf("invalid regex pattern for %s: %w", fieldType, err)
	}
	if !matched {
		return fmt.Errorf("%s '%s' does not match required pattern '%s'", fieldType, value, pattern)
	}
	return nil
}
