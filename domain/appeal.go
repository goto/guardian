package domain

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"

	"github.com/goto/guardian/pkg/diff"
	"github.com/goto/guardian/pkg/evaluator"
	"github.com/goto/guardian/pkg/slices"
	"github.com/goto/guardian/utils"
)

const (
	AppealActionNameApprove = "approve"
	AppealActionNameReject  = "reject"

	AppealStatusPending  = "pending"
	AppealStatusCanceled = "canceled"
	AppealStatusApproved = "approved"
	AppealStatusRejected = "rejected"

	SystemActorName = "system"

	DefaultAppealAccountType = "user"
	PermanentDurationLabel   = "Permanent"

	ExpirationDateReasonFromAppeal = "Expiration date is set based on the appeal options"

	ReservedDetailsKeyProviderParameters = "__provider_parameters"
	ReservedDetailsKeyPolicyQuestions    = "__policy_questions"
	ReservedDetailsKeyPolicyMetadata     = "__policy_metadata"
)

var (
	ErrFailedToGetApprovers   = errors.New("failed to get approvers")
	ErrApproversNotFound      = errors.New("approvers not found")
	ErrUnexpectedApproverType = errors.New("unexpected approver type")
	ErrInvalidApproverValue   = errors.New("approver value is not a valid email")
)

// AppealOptions
type AppealOptions struct {
	ExpirationDate *time.Time `json:"expiration_date,omitempty" yaml:"expiration_date,omitempty"`
	Duration       string     `json:"duration,omitempty" yaml:"duration,omitempty"`
}

// LabelMetadata contains rich information about how a label was derived
type LabelMetadata struct {
	// Value is the label value (duplicate from Labels map for convenience)
	Value string `json:"value" yaml:"value"`

	// DerivedFrom is the rule name that applied this label (e.g., "rule_pii")
	// For user labels: "user" or "user:<email>"
	DerivedFrom string `json:"derived_from" yaml:"derived_from"`

	// Source identifies the label source
	Source LabelSource `json:"source" yaml:"source"`

	// Category groups labels (resource, account, requestor, environment, etc.)
	// Extracted from namespaced key or defined in rule
	Category string `json:"category,omitempty" yaml:"category,omitempty"`

	// Attributes contains arbitrary metadata about the label
	// Examples: {"risk": "sensitivity", "retention_policy": "90_days"}
	Attributes map[string]interface{} `json:"attributes,omitempty" yaml:"attributes,omitempty"`

	// AppliedBy is the user email who applied user labels
	// Only populated for user labels
	AppliedBy string `json:"applied_by,omitempty" yaml:"applied_by,omitempty"`

	// AppliedAt timestamp when label was applied
	AppliedAt time.Time `json:"applied_at" yaml:"applied_at"`
}

// LabelSource identifies where a label originated
type LabelSource string

const (
	LabelSourcePolicyRule LabelSource = "policy_rule" // From policy labeling rules
	LabelSourceUser       LabelSource = "user"        // User-provided user label
	LabelSourceProvider   LabelSource = "provider"    // Future: from provider
	LabelSourceExternal   LabelSource = "external"    // Future: from external API
)

// Appeal struct
type Appeal struct {
	ID            string                 `json:"id" yaml:"id"`
	ResourceID    string                 `json:"resource_id" yaml:"resource_id"`
	PolicyID      string                 `json:"policy_id" yaml:"policy_id"`
	PolicyVersion uint                   `json:"policy_version" yaml:"policy_version"`
	Status        string                 `json:"status" yaml:"status"`
	AccountID     string                 `json:"account_id" yaml:"account_id"`
	AccountType   string                 `json:"account_type" yaml:"account_type" default:"user"`
	GroupID       string                 `json:"group_id,omitempty" yaml:"group_id,omitempty"`
	GroupType     string                 `json:"group_type,omitempty" yaml:"group_type,omitempty"`
	CreatedBy     string                 `json:"created_by" yaml:"created_by"`
	Creator       interface{}            `json:"creator" yaml:"creator"`
	Role          string                 `json:"role" yaml:"role"`
	Permissions   []string               `json:"permissions" yaml:"permissions"`
	Options       *AppealOptions         `json:"options" yaml:"options"`
	Details       map[string]interface{} `json:"details" yaml:"details"`

	// UserLabels are user-provided labels (input field, not persisted as-is)
	UserLabels map[string]string `json:"user_labels,omitempty" yaml:"user_labels,omitempty"`

	// Labels: Flat key-value map for efficient filtering and backward compatibility
	// Keys use namespaced format for categorization: "category:key" or "key" for global
	// Examples: "resource:pii", "account:type", "environment", "risk_level"
	Labels map[string]string `json:"labels" yaml:"labels"`

	// LabelsMetadata: Rich metadata about each label (optional, for audit/reporting)
	// Only populated if policy rules define metadata
	// Key matches the key in Labels map
	LabelsMetadata map[string]*LabelMetadata `json:"labels_metadata,omitempty" yaml:"labels_metadata,omitempty"`

	Description string `json:"description" yaml:"description"`

	Policy    *Policy     `json:"-" yaml:"-"`
	Resource  *Resource   `json:"resource,omitempty" yaml:"resource,omitempty"`
	Approvals []*Approval `json:"approvals,omitempty" yaml:"approvals,omitempty"`
	Grant     *Grant      `json:"grant,omitempty" yaml:"grant,omitempty"`

	Revision uint `json:"revision,omitempty" yaml:"revision,omitempty"`

	CreatedAt time.Time `json:"created_at,omitempty" yaml:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
}

func (a *Appeal) Init(policy *Policy) {
	a.Status = AppealStatusPending
	a.PolicyID = policy.ID
	a.PolicyVersion = policy.Version
}

func (a *Appeal) Cancel() {
	a.Status = AppealStatusCanceled
}

func (a *Appeal) Approve() error {
	a.Status = AppealStatusApproved

	duration, err := a.GetDuration()
	if err != nil {
		return err
	}

	// for permanent access duration is equal to zero
	if duration == 0*time.Second {
		return nil
	}

	expirationDate := time.Now().Add(duration)
	a.Options.ExpirationDate = &expirationDate
	return nil
}

func (a *Appeal) GetDuration() (time.Duration, error) {
	if a.IsDurationEmpty() {
		return 0 * time.Second, nil
	}

	duration, err := time.ParseDuration(a.Options.Duration)
	if err != nil {
		return 0 * time.Second, err
	}

	return duration, nil
}

func (a *Appeal) IsDurationEmpty() bool {
	return a.Options == nil || a.Options.Duration == "" || a.Options.Duration == "0h"
}

func (a *Appeal) Reject() {
	a.Status = AppealStatusRejected
}

func (a *Appeal) SetDefaults() {
	if a.AccountType == "" {
		a.AccountType = DefaultAppealAccountType
	}
}

// GetApproval returns an approval within the appeal.
// If the ID is provided, it will return the approval with the given ID.
// If the name is provided, it will return the approval with the given name AND !is_stale.
func (a *Appeal) GetApproval(identifier string) *Approval {
	for _, approval := range a.Approvals {
		if approval.ID == identifier || (approval.Name == identifier && !approval.IsStale) {
			return approval
		}
	}
	return nil
}

func (a *Appeal) GetApprovalByIndex(index int) *Approval {
	for _, approval := range a.Approvals {
		if approval.Index == index && !approval.IsStale {
			return approval
		}
	}
	return nil
}

func (a *Appeal) GetNextPendingApproval() *Approval {
	for _, approval := range a.Approvals {
		if approval.Status == ApprovalStatusPending && approval.IsManualApproval() && !approval.IsStale {
			return approval
		}
	}
	return nil
}

func (a Appeal) ToGrant() (*Grant, error) {
	grant := &Grant{
		Status:      GrantStatusActive,
		AccountID:   a.AccountID,
		AccountType: a.AccountType,
		GroupID:     a.GroupID,
		GroupType:   a.GroupType,
		ResourceID:  a.ResourceID,
		Role:        a.Role,
		Permissions: a.Permissions,
		AppealID:    a.ID,
		CreatedBy:   a.CreatedBy,
	}

	// Validate that both ExpirationDate and Duration are not provided
	if a.Options != nil && a.Options.ExpirationDate != nil && a.Options.Duration != "" {
		return nil, fmt.Errorf("cannot specify both expiration_date and duration, please provide only one")
	}

	// Priority: ExpirationDate > Duration
	if a.Options != nil && a.Options.ExpirationDate != nil {
		// User provided exact expiration date
		expDate := *a.Options.ExpirationDate
		duration := time.Until(expDate)
		if duration <= 0 {
			return nil, fmt.Errorf("expiration date must be in the future, got: %v", expDate)
		}

		grant.ExpirationDate = &expDate
		grant.RequestedExpirationDate = &expDate
		grant.ExpirationDateReason = ExpirationDateReasonFromAppeal

		// Calculate and set Duration based on ExpirationDate
		hours := int(duration.Hours())
		a.Options.Duration = fmt.Sprintf("%dh", hours)
	} else if a.Options != nil && a.Options.Duration != "" {
		// User provided duration string
		duration, err := time.ParseDuration(a.Options.Duration)
		if err != nil {
			return nil, fmt.Errorf("parsing duration %q: %w", a.Options.Duration, err)
		}
		if duration == 0 {
			grant.IsPermanent = true
		} else {
			expDate := time.Now().Add(duration)
			grant.ExpirationDate = &expDate
			grant.RequestedExpirationDate = &expDate
			grant.ExpirationDateReason = ExpirationDateReasonFromAppeal
		}
	} else {
		grant.IsPermanent = true
	}

	return grant, nil
}

func (a *Appeal) ApplyPolicy(p *Policy) error {
	approvals := []*Approval{}
	for i, step := range p.Steps {
		approval, err := step.ToApproval(a, p, i)
		if err != nil {
			return err
		}
		approvals = append(approvals, approval)
	}

	a.Approvals = approvals
	a.Init(p)
	a.Policy = p

	return nil
}

func (a *Appeal) AdvanceApproval(policy *Policy) error {
	if policy == nil {
		return fmt.Errorf("appeal has no policy")
	}

	policyStepCount := len(policy.Steps)
	totalStepCount := policyStepCount
	if policy.HasCustomSteps() {
		nonStaleCount := 0
		for _, approval := range a.Approvals {
			if !approval.IsStale {
				nonStaleCount++
			}
		}
		totalStepCount = nonStaleCount
	}
	for i := 0; i < totalStepCount; i++ {
		approval := a.GetApprovalByIndex(i)
		if approval == nil {
			return fmt.Errorf(`unable to find approval with index %q under policy "%s:%d"`, i, policy.ID, policy.Version)
		}

		if approval.Status == ApprovalStatusRejected {
			break
		}
		if approval.Status == ApprovalStatusPending {
			if i < policyStepCount {
				stepConfig := policy.Steps[approval.Index]

				appealMap, err := a.ToMap()
				if err != nil {
					return fmt.Errorf("parsing appeal struct to map: %w", err)
				}

				if stepConfig.When != "" {
					v, err := evaluator.Expression(stepConfig.When).EvaluateWithVars(map[string]interface{}{
						"appeal": appealMap,
					})
					if err != nil {
						return err
					}

					isFalsy := reflect.ValueOf(v).IsZero()
					if isFalsy {
						// mark current as skipped
						approval.Status = ApprovalStatusSkipped

						// mark next as pending
						nextApproval := a.GetApprovalByIndex(approval.Index + 1)
						if nextApproval != nil {
							nextApproval.Status = ApprovalStatusPending
						}
					}
				}

				if approval.Status != ApprovalStatusSkipped && stepConfig.Strategy == ApprovalStepStrategyAuto {
					v, err := evaluator.Expression(stepConfig.ApproveIf).EvaluateWithVars(map[string]interface{}{
						"appeal": appealMap,
					})
					if err != nil {
						return err
					}
					isFalsy := reflect.ValueOf(v).IsZero()
					if isFalsy {
						if stepConfig.AllowFailed {
							// mark current as skipped
							approval.Status = ApprovalStatusSkipped

							// mark next as pending
							nextApproval := a.GetApprovalByIndex(approval.Index + 1)
							if nextApproval != nil {
								nextApproval.Status = ApprovalStatusPending
							}
						} else {
							approval.Status = ApprovalStatusRejected
							evaluatedRejectionReason, err := evaluateExpressionWithAppeal(a, stepConfig.RejectionReason)
							if err != nil {
								return err
							}
							approval.Reason = evaluatedRejectionReason
							a.Status = AppealStatusRejected
						}
					} else {
						// mark current as approved
						approval.Status = ApprovalStatusApproved

						// mark next as pending
						nextApproval := a.GetApprovalByIndex(approval.Index + 1)
						if nextApproval != nil {
							nextApproval.Status = ApprovalStatusPending
						}
					}
				}
			}
		}
		isLastApproval := approval.Index == totalStepCount-1
		if isLastApproval && (approval.Status == ApprovalStatusSkipped || approval.Status == ApprovalStatusApproved) {
			a.Status = AppealStatusApproved
		}
	}

	return nil
}

func (a *Appeal) DryRunAdvanceApproval(policy *Policy) error {
	if err := a.AdvanceApproval(policy); err != nil {
		return err
	}

	appealMap, err := a.ToMap()
	if err != nil {
		return fmt.Errorf("parsing appeal struct to map: %w", err)
	}

	for i := range a.Approvals {
		approval := a.Approvals[i]
		if !slices.GenericsSliceContainsOne([]string{ApprovalStatusBlocked, ApprovalStatusPending}, approval.Status) {
			continue
		}
		stepConfig := policy.Steps[approval.Index]
		if stepConfig.When != "" {
			v, err := evaluator.Expression(stepConfig.When).EvaluateWithVars(map[string]interface{}{
				"appeal": appealMap,
			})
			if err != nil {
				return err
			}
			isFalsy := reflect.ValueOf(v).IsZero()
			if isFalsy {
				// mark current as skipped
				approval.Status = ApprovalStatusSkipped
			}
		}
		a.Approvals[i] = approval
	}

	return nil
}

func (a *Appeal) ToMap() (map[string]interface{}, error) {
	return utils.StructToMap(a)
}

func (a *Appeal) getComparable() Appeal {
	copy := *a
	copy.ID = ""
	copy.Policy = nil
	copy.Resource = nil
	copy.Approvals = nil
	copy.Grant = nil
	copy.CreatedAt = time.Time{}
	copy.UpdatedAt = time.Time{}
	return copy
}

func (a *Appeal) Compare(old *Appeal, actor string) ([]*DiffItem, error) {
	if a == nil {
		return nil, fmt.Errorf("cannot compare nil appeal")
	}
	if old == nil {
		return nil, fmt.Errorf("cannot compare with nil appeal")
	}
	if actor == "" {
		return nil, fmt.Errorf("actor is required")
	}

	oldComparable := old.getComparable()
	newComparable := a.getComparable()
	changes, err := diff.Compare(oldComparable, newComparable)
	if err != nil {
		return nil, err
	}

	diffItems := make([]*DiffItem, 0, len(changes))
	for _, c := range changes {
		diff := &DiffItem{
			Op:       c.Op,
			Path:     c.Path,
			OldValue: c.OldValue,
			NewValue: c.NewValue,
		}

		switch {
		case c.Path == "policy_id",
			c.Path == "policy_version",
			c.Path == "status",
			c.Path == "creator",
			c.Path == "revision",
			strings.HasPrefix(c.Path, "permissions"),
			strings.HasPrefix(c.Path, fmt.Sprintf("details.%s", ReservedDetailsKeyPolicyMetadata)):
			diff.Actor = SystemActorName
		default:
			diff.Actor = actor
		}

		diffItems = append(diffItems, diff)
	}
	return diffItems, nil
}

type ApprovalActionType string

const (
	ApprovalActionApprove ApprovalActionType = "approve"
	ApprovalActionReject  ApprovalActionType = "reject"
)

type ApprovalAction struct {
	AppealID     string `validate:"required" json:"appeal_id"`
	ApprovalName string `validate:"required" json:"approval_name"`
	Actor        string `validate:"email" json:"actor"`
	Action       string `validate:"required,oneof=approve reject" json:"action"`
	Reason       string `json:"reason"`
}

func (a ApprovalAction) Validate() error {
	if a.AppealID == "" {
		return fmt.Errorf("appeal id is required")
	}
	if a.ApprovalName == "" {
		return fmt.Errorf("approval name is required")
	}
	if validator.New().Var(a.Actor, "email") != nil {
		return fmt.Errorf("actor is not a valid email: %q", a.Actor)
	}
	if a.Action != string(ApprovalActionApprove) && a.Action != string(ApprovalActionReject) {
		return fmt.Errorf("invalid action: %q", a.Action)
	}
	return nil
}

type ListAppealsFilter struct {
	Q                         string    `mapstructure:"q" validate:"omitempty"`
	AccountTypes              []string  `mapstructure:"account_types" validate:"omitempty,min=1"`
	CreatedBy                 string    `mapstructure:"created_by" validate:"omitempty,required"`
	AccountID                 string    `mapstructure:"account_id" validate:"omitempty,required"`
	AccountIDs                []string  `mapstructure:"account_ids" validate:"omitempty,required"`
	GroupIDs                  []string  `mapstructure:"group_ids" validate:"omitempty,required"`
	GroupTypes                []string  `mapstructure:"group_types" validate:"omitempty,min=1"`
	ResourceID                string    `mapstructure:"resource_id" validate:"omitempty,required"`
	Role                      string    `mapstructure:"role" validate:"omitempty,required"`
	Roles                     []string  `mapstructure:"role" validate:"omitempty,required"`
	Statuses                  []string  `mapstructure:"statuses" validate:"omitempty,min=1"`
	ExpirationDateLessThan    time.Time `mapstructure:"expiration_date_lt" validate:"omitempty,required"`
	ExpirationDateGreaterThan time.Time `mapstructure:"expiration_date_gt" validate:"omitempty,required"`
	ProviderTypes             []string  `mapstructure:"provider_types" validate:"omitempty,min=1"`
	ProviderURNs              []string  `mapstructure:"provider_urns" validate:"omitempty,min=1"`
	ResourceTypes             []string  `mapstructure:"resource_types" validate:"omitempty,min=1"`
	ResourceURNs              []string  `mapstructure:"resource_urns" validate:"omitempty,min=1"`
	OrderBy                   []string  `mapstructure:"order_by" validate:"omitempty,min=1"`
	Size                      int       `mapstructure:"size" validate:"omitempty"`
	Offset                    int       `mapstructure:"offset" validate:"omitempty"`
	ResourceIDs               []string  `mapstructure:"resource_ids" validate:"omitempty,min=1"`
	SummaryGroupBys           []string  `mapstructure:"summary_group_bys" validate:"omitempty"`
	SummaryUniques            []string  `mapstructure:"summary_uniques" validate:"omitempty"`
	FieldMasks                []string  `mapstructure:"field_masks" validate:"omitempty"`
	RoleStartsWith            string    `mapstructure:"role_starts_with" validate:"omitempty"`
	RoleEndsWith              string    `mapstructure:"role_ends_with" validate:"omitempty"`
	RoleContains              string    `mapstructure:"role_contains" validate:"omitempty"`
	StartTime                 time.Time `mapstructure:"start_time" validate:"omitempty"`
	EndTime                   time.Time `mapstructure:"end_time" validate:"omitempty"`
	WithApprovals             bool      `mapstructure:"with_approvals" validate:"omitempty"`
	ProviderUrnStartsWith     string    `mapstructure:"provider_urn_starts_with" json:"provider_urn_starts_with,omitempty" validate:"omitempty"`
	ProviderUrnEndsWith       string    `mapstructure:"provider_urn_ends_with" json:"provider_urn_ends_with,omitempty" validate:"omitempty"`
	ProviderUrnContains       string    `mapstructure:"provider_urn_contains" json:"provider_urn_contains,omitempty" validate:"omitempty"`
	ProviderUrnNotStartsWith  string    `mapstructure:"provider_urn_not_starts_with" json:"provider_urn_not_starts_with,omitempty" validate:"omitempty"`
	ProviderUrnNotEndsWith    string    `mapstructure:"provider_urn_not_ends_with" json:"provider_urn_not_ends_with,omitempty" validate:"omitempty"`
	ProviderUrnNotContains    string    `mapstructure:"provider_urn_not_contains" json:"provider_urn_not_contains,omitempty" validate:"omitempty"`
	Durations                 []string  `mapstructure:"durations" json:"durations,omitempty" validate:"omitempty"`
	NotDurations              []string  `mapstructure:"not_durations" json:"not_durations,omitempty" validate:"omitempty"`
	DetailsPaths              []string  `mapstructure:"details_paths" json:"details_paths,omitempty" validate:"omitempty"`
	Details                   []string  `mapstructure:"details" json:"details,omitempty" validate:"omitempty"`
	NotDetails                []string  `mapstructure:"not_details" json:"not_details,omitempty" validate:"omitempty"`

	// Labels filters appeals by label key-value pairs
	// Format: map[key][]values (OR within values, AND across keys)
	// Example: {"environment": ["production", "staging"], "data_layer": ["raw"]}
	// Matches: (environment=production OR environment=staging) AND data_layer=raw
	Labels map[string][]string `mapstructure:"labels" validate:"omitempty"`

	// LabelKeys filters appeals that have ANY of these label keys (regardless of value)
	// Example: ["pii_access", "compliance_required"]
	LabelKeys []string `mapstructure:"label_keys" validate:"omitempty,min=1"`

	RoleNotStartsWith         string   `mapstructure:"role_not_starts_with" json:"role_not_starts_with,omitempty" validate:"omitempty"`
	RoleNotEndsWith           string   `mapstructure:"role_not_ends_with" json:"role_not_ends_with,omitempty" validate:"omitempty"`
	RoleNotContains           string   `mapstructure:"role_not_contains" json:"role_not_contains,omitempty" validate:"omitempty"`
	DetailsStartsWith         string   `mapstructure:"details_starts_with" validate:"omitempty"`
	DetailsEndsWith           string   `mapstructure:"details_ends_with" validate:"omitempty"`
	DetailsContains           string   `mapstructure:"details_contains" validate:"omitempty"`
	DetailsNotStartsWith      string   `mapstructure:"details_not_starts_with" validate:"omitempty"`
	DetailsNotEndsWith        string   `mapstructure:"details_not_ends_with" validate:"omitempty"`
	DetailsNotContains        string   `mapstructure:"details_not_contains" validate:"omitempty"`
	GroupTypeStartsWith       string   `mapstructure:"group_type_starts_with" validate:"omitempty"`
	GroupTypeEndsWith         string   `mapstructure:"group_type_ends_with" validate:"omitempty"`
	GroupTypeContains         string   `mapstructure:"group_type_contains" validate:"omitempty"`
	GroupTypeNotStartsWith    string   `mapstructure:"group_type_not_starts_with" validate:"omitempty"`
	GroupTypeNotEndsWith      string   `mapstructure:"group_type_not_ends_with" validate:"omitempty"`
	GroupTypeNotContains      string   `mapstructure:"group_type_not_contains" validate:"omitempty"`
	IDs                       []string `mapstructure:"ids" validate:"omitempty"`
	NotIDs                    []string `mapstructure:"not_ids" validate:"omitempty"`
	DetailsForSelfCriteria    []string `mapstructure:"details_for_self_criteria" json:"details_for_self_criteria,omitempty" validate:"omitempty"`
	NotDetailsForSelfCriteria []string `mapstructure:"not_details_for_self_criteria" json:"not_details_for_self_criteria,omitempty" validate:"omitempty"`
	SummaryLabels             bool     `mapstructure:"summary_labels" json:"summary_labels,omitempty" validate:"omitempty"`
}

func (af ListAppealsFilter) WithSummary() bool {
	return len(af.SummaryGroupBys) > 0 || len(af.SummaryUniques) > 0 || af.SummaryLabels
}

func (af ListAppealsFilter) WithAppeals() bool {
	return !slices.GenericsSliceContainsOne(af.FieldMasks, "appeals")
}

func (af ListAppealsFilter) WithTotal() bool {
	return !slices.GenericsSliceContainsOne(af.FieldMasks, "total")
}

type DiffItem struct {
	Op       string `json:"op"`
	Actor    string `json:"actor"`
	Path     string `json:"path"`
	OldValue any    `json:"old_value,omitempty"`
	NewValue any    `json:"new_value,omitempty"`
}

func evaluateExpressionWithAppeal(a *Appeal, expression string) (string, error) {
	if expression != "" && strings.Contains(expression, "$appeal") {
		appealMap, err := a.ToMap()
		if err != nil {
			return "", fmt.Errorf("error converting appeal to map: %w", err)
		}
		params := map[string]interface{}{"appeal": appealMap}
		evaluated, err := evaluator.Expression(expression).EvaluateWithVars(params)
		if err != nil {
			return "", fmt.Errorf("error evaluating expression %w", err)
		}
		evaluatedStr, ok := evaluated.(string)
		if !ok {
			return "", fmt.Errorf("expression must evaluate to a string")
		}
		return evaluatedStr, nil
	}
	return expression, nil
}
