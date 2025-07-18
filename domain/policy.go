package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/goto/guardian/pkg/evaluator"
	"github.com/goto/guardian/pkg/slices"
	"github.com/goto/guardian/utils"
	"github.com/mcuadros/go-lookup"
)

const (
	ApproversKeyResource = "$resource"
)

var (
	ErrInvalidConditionField = errors.New("unable to parse condition's field")

	validate = validator.New()
)

type ApprovalStepStrategy string

const (
	ApprovalStepStrategyAuto   ApprovalStepStrategy = "auto"
	ApprovalStepStrategyManual ApprovalStepStrategy = "manual"
)

// MatchCondition is for determining the requirement of the condition
type MatchCondition struct {
	Eq interface{} `json:"eq" yaml:"eq"`
}

// Condition gets evaluated to determine the approval step resolution whether it is success or failed
type Condition struct {
	Field string          `json:"field" yaml:"field" validate:"required"`
	Match *MatchCondition `json:"match" yaml:"match" validate:"required"`
}

func (c *Condition) IsMatch(a *Appeal) (bool, error) {
	if strings.HasPrefix(c.Field, ApproversKeyResource) {
		jsonString, err := json.Marshal(a.Resource)
		if err != nil {
			return false, err
		}
		var resourceMap map[string]interface{}
		if err := json.Unmarshal(jsonString, &resourceMap); err != nil {
			return false, err
		}

		path := strings.TrimPrefix(c.Field, fmt.Sprintf("%s.", ApproversKeyResource))
		value, err := lookup.LookupString(resourceMap, path)
		if err != nil {
			return false, err
		}

		expectedValue := c.Match.Eq
		return value.Interface() == expectedValue, nil
	}

	return false, fmt.Errorf("evaluating field: %v: %v", c.Field, ErrInvalidConditionField)
}

// Step is an individual process within an approval flow
type Step struct {
	// Name used as the step identifier
	Name string `json:"name" yaml:"name" validate:"required"`

	// Description tells more details about the step
	Description string `json:"description" yaml:"description"`

	// AllowFailed lets the approval flow continue to the next step even the current step is rejected.
	// If the last step has AllowFailed equal to true, and it's getting rejected,
	// the appeal status will resolve as approved or success.
	AllowFailed bool `json:"allow_failed" yaml:"allow_failed"`

	// When is an Expression that determines whether the step should be evaluated or it can be skipped at the beginning.
	// If it evaluates to be falsy, the step will automatically skipped. Otherwise, step become pending/blocked (normal).
	//
	// Accessible parameters:
	// $appeal = Appeal object
	When string `json:"when,omitempty" yaml:"when,omitempty"`

	// Strategy defines if the step requires manual approval or not
	Strategy ApprovalStepStrategy `json:"strategy" yaml:"strategy" validate:"required,oneof=auto manual"`

	// RejectionReason message fills `Approval.Reason` if the approval step gets rejected based on `ApproveIf` expression.
	RejectionReason string `json:"rejection_reason" yaml:"rejection_reason"`

	// Approvers is an Expression that if the evaluation returns string or []string that contains email address of the approvers.
	// If human approval (manual) is required, use this field.
	//
	// Accessible parameters:
	// $appeal = Appeal object
	Approvers []string `json:"approvers,omitempty" yaml:"approvers,omitempty" validate:"required_if=Strategy manual,omitempty,min=1"`

	// ApproveIf is an Expression to determines the resolution of the step. If automatic approval is needed for the step,
	// use this field.
	//
	// Accessible parameters:
	// $appeal = Appeal object
	ApproveIf string `json:"approve_if,omitempty" yaml:"approve_if,omitempty" validate:"required_if=Strategy auto"`

	// DontAllowSelfApproval is a boolean flag to detemine if the approver can approve their own request.
	DontAllowSelfApproval bool `json:"dont_allow_self_approval,omitempty" yaml:"dont_allow_self_approval,omitempty"`
}

func (s Step) ResolveApprovers(a *Appeal) ([]string, error) {
	if s.Strategy != ApprovalStepStrategyManual {
		return nil, nil
	}

	var approvers []string

	for _, expr := range s.Approvers {
		if err := validate.Var(expr, "email"); err == nil {
			approvers = append(approvers, expr)
		} else {
			appealMap, err := utils.StructToMap(a)
			if err != nil {
				return nil, fmt.Errorf("parsing appeal to map: %w", err)
			}
			params := map[string]interface{}{
				"appeal": appealMap,
			}

			approversValue, err := evaluator.Expression(expr).EvaluateWithVars(params)
			if err != nil {
				return nil, fmt.Errorf("%w: %s", ErrFailedToGetApprovers, err)
			} else if approversValue == nil {
				return nil, ErrApproversNotFound
			}

			value := reflect.ValueOf(approversValue)
			switch value.Type().Kind() {
			case reflect.String:
				approvers = append(approvers, value.String())
			case reflect.Slice:
				for i := 0; i < value.Len(); i++ {
					itemValue := reflect.ValueOf(value.Index(i).Interface())
					switch itemValue.Type().Kind() {
					case reflect.String:
						approvers = append(approvers, itemValue.String())
					default:
						return nil, fmt.Errorf(`%w: %q`, ErrUnexpectedApproverType, itemValue.Type().Kind())
					}
				}
			default:
				return nil, fmt.Errorf(`%w: %q`, ErrUnexpectedApproverType, value.Type().Kind())
			}
		}
	}

	uniqueApprovers := slices.UniqueStringSlice(approvers)
	for _, approverEmail := range uniqueApprovers {
		if err := validate.Var(approverEmail, "email"); err != nil {
			return nil, fmt.Errorf("%w: %q", ErrInvalidApproverValue, approverEmail)
		}
	}

	return uniqueApprovers, nil
}

func (s Step) ToApproval(a *Appeal, p *Policy, index int) (*Approval, error) {
	approvers, err := s.ResolveApprovers(a)
	if err != nil {
		return nil, fmt.Errorf("unable to set approvers for %q: %w", s.Name, err)
	}

	approval := &Approval{
		Index:          index,
		Name:           s.Name,
		PolicyID:       p.ID,
		PolicyVersion:  p.Version,
		Approvers:      approvers,
		Status:         ApprovalStatusPending,
		AppealRevision: a.Revision,
		IsStale:        false,
	}

	if index > 0 {
		approval.Status = ApprovalStatusBlocked
	}

	return approval, nil
}

type RequirementTrigger struct {
	ProviderType string `json:"provider_type" yaml:"provider_type" validate:"required_without_all=ProviderURN ResourceType ResourceURN Role Conditions Expression"`
	ProviderURN  string `json:"provider_urn" yaml:"provider_urn" validate:"required_without_all=ProviderType ResourceType ResourceURN Role Conditions Expression"`
	ResourceType string `json:"resource_type" yaml:"resource_type" validate:"required_without_all=ProviderType ProviderURN ResourceURN Role Conditions Expression"`
	ResourceURN  string `json:"resource_urn" yaml:"resource_urn" validate:"required_without_all=ProviderType ProviderURN ResourceType Role Conditions Expression"`
	Role         string `json:"role" yaml:"role" validate:"required_without_all=ProviderType ProviderURN ResourceType ResourceType Conditions Expression"`
	// Deprecated: use Expression instead
	Conditions []*Condition `json:"conditions" yaml:"conditions" validate:"required_without_all=ProviderType ProviderURN ResourceType ResourceType Role Expression"`
	Expression string       `json:"expression" yaml:"expression" validate:"required_without_all=ProviderType ProviderURN ResourceType ResourceType Role Conditions"`
}

func (r *RequirementTrigger) IsMatch(a *Appeal) (bool, error) {
	if r.ProviderType != "" {
		if match, err := regexp.MatchString(r.ProviderType, a.Resource.ProviderType); err != nil {
			return match, err
		} else if !match {
			return match, nil
		}
	}
	if r.ProviderURN != "" {
		if match, err := regexp.MatchString(r.ProviderURN, a.Resource.ProviderURN); err != nil {
			return match, err
		} else if !match {
			return match, nil
		}
	}
	if r.ResourceType != "" {
		if match, err := regexp.MatchString(r.ResourceType, a.Resource.Type); err != nil {
			return match, err
		} else if !match {
			return match, nil
		}
	}
	if r.ResourceURN != "" {
		if match, err := regexp.MatchString(r.ResourceURN, a.Resource.URN); err != nil {
			return match, err
		} else if !match {
			return match, nil
		}
	}
	if r.Role != "" {
		if match, err := regexp.MatchString(r.Role, a.Role); err != nil {
			return match, err
		} else if !match {
			return match, nil
		}
	}
	if r.Conditions != nil {
		for i, c := range r.Conditions {
			if match, err := c.IsMatch(a); err != nil {
				return match, fmt.Errorf("evaluating conditions[%v]: %v", i, err)
			} else if !match {
				return match, nil
			}
		}
	}
	if r.Expression != "" {
		appealMap, err := utils.StructToMap(a)
		if err != nil {
			return false, fmt.Errorf("parsing appeal to map: %w", err)
		}
		params := map[string]interface{}{"appeal": appealMap}
		v, err := evaluator.Expression(r.Expression).EvaluateWithVars(params)
		if err != nil {
			return false, fmt.Errorf("evaluating expression %q: %w", r.Expression, err)
		}
		if match, ok := v.(bool); !ok {
			return false, fmt.Errorf("expression %q did not evaluate to a boolean, evaluated value: %q", r.Expression, v)
		} else {
			return match, nil
		}
	}

	return true, nil
}

type ResourceIdentifier struct {
	ProviderType string `json:"provider_type" yaml:"provider_type" validate:"required_with=ProviderURN Type URN"`
	ProviderURN  string `json:"provider_urn" yaml:"provider_urn" validate:"required_with=ProviderType Type URN"`
	Type         string `json:"type" yaml:"type" validate:"required_with=ProviderType ProviderURN URN"`
	URN          string `json:"urn" yaml:"urn" validate:"required_with=ProviderType ProviderURN Type"`
	ID           string `json:"id" yaml:"id" validate:"required_without_all=ProviderType ProviderURN Type URN"`
}

type AdditionalAppeal struct {
	Resource    *ResourceIdentifier `json:"resource" yaml:"resource"  validate:"required"`
	Role        string              `json:"role" yaml:"role" validate:"required"`
	Options     *AppealOptions      `json:"options" yaml:"options"`
	Policy      *PolicyConfig       `json:"policy" yaml:"policy"`
	AccountType string              `json:"account_type" yaml:"account_type"`
}

type Requirement struct {
	On      *RequirementTrigger `json:"on" yaml:"on" validate:"required"`
	Appeals []*AdditionalAppeal `json:"appeals" yaml:"appeals" validate:"required,min=1,dive"`
}

// Policy is the approval policy configuration
type Policy struct {
	ID           string              `json:"id" yaml:"id" validate:"required"`
	Version      uint                `json:"version" yaml:"version" validate:"required"`
	Description  string              `json:"description" yaml:"description"`
	Steps        []*Step             `json:"steps" yaml:"steps" validate:"required,min=1,dive"`
	AppealConfig *PolicyAppealConfig `json:"appeal" yaml:"appeal" validate:"omitempty,dive"`
	Requirements []*Requirement      `json:"requirements,omitempty" yaml:"requirements,omitempty" validate:"omitempty,min=1,dive"`
	Labels       map[string]string   `json:"labels,omitempty" yaml:"labels,omitempty"`
	IAM          *IAMConfig          `json:"iam,omitempty" yaml:"iam,omitempty" validate:"omitempty,dive"`
	CreatedAt    time.Time           `json:"created_at,omitempty" yaml:"created_at,omitempty"`
	UpdatedAt    time.Time           `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
}

func (p *Policy) RemoveSensitiveValues() {
	if p.IAM != nil {
		p.IAM.Config = nil
	}
	if p.AppealConfig != nil {
		for key := range p.AppealConfig.MetadataSources {
			p.AppealConfig.MetadataSources[key].Config = nil
		}
	}
}

func (p *Policy) GetStepByName(name string) *Step {
	for _, step := range p.Steps {
		if step.Name == name {
			return step
		}
	}
	return nil
}

type PolicyAppealConfig struct {
	DurationOptions              []AppealDurationOption `json:"duration_options" yaml:"duration_options" validate:"omitempty,min=1,dive"`
	AllowOnBehalf                bool                   `json:"allow_on_behalf" yaml:"allow_on_behalf"`
	AllowPermanentAccess         bool                   `json:"allow_permanent_access" yaml:"allow_permanent_access"`
	AllowActiveAccessExtensionIn string                 `json:"allow_active_access_extension_in" yaml:"allow_active_access_extension_in"`
	Questions                    []Question             `json:"questions" yaml:"questions"`
	// AllowCreatorDetailsFailure is a flag that lets the appeal creation to continue when the request to the identity
	// provider (Policy.IAM) fails. If this is set to true and request to the identity provider fails (4xx or 5xx), the
	// value of `creator` field in the appeal will be nil.
	// Note: any expression that tries to access `$appeal.creator.*` is still evaluated as usual, it might need to have
	// proper nil checking to avoid accessing nil value.
	AllowCreatorDetailsFailure bool                             `json:"allow_creator_details_failure" yaml:"allow_creator_details_failure"`
	MetadataSources            map[string]*AppealMetadataSource `json:"metadata_sources,omitempty" yaml:"metadata_sources,omitempty"`
}

type Question struct {
	Key         string `json:"key" yaml:"key"`
	Question    string `json:"question" yaml:"question"`
	Required    bool   `json:"required" yaml:"required"`
	Description string `json:"description" yaml:"description"`
}

type AppealDurationOption struct {
	// Name of the duration
	// Ex: 1 Day, 3 Days, Permanent
	Name string `json:"name" yaml:"name" validate:"required"`
	// Value of the actual duration
	// Ex: 24h, 72h, 0h
	// `0h` is reserved for permanent access
	Value string `json:"value" yaml:"value" validate:"required"`
}

func (p *Policy) HasIAMConfig() bool {
	return p.IAM != nil
}

func (p *Policy) HasAppealMetadataSources() bool {
	return p.AppealConfig != nil && p.AppealConfig.MetadataSources != nil
}
