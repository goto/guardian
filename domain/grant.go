package domain

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	guardianv1beta1 "github.com/goto/guardian/api/proto/gotocompany/guardian/v1beta1"
	"github.com/goto/guardian/pkg/diff"
	"github.com/goto/guardian/pkg/slices"
)

type GrantStatus string
type GrantSource string

const (
	GrantStatusActive   GrantStatus = "active"
	GrantStatusInactive GrantStatus = "inactive"

	GrantSourceAppeal GrantSource = "appeal"
	GrantSourceImport GrantSource = "import"

	GrantExpirationReasonDormant  = "grant/access hasn't been used for a while"
	GrantExpirationReasonRestored = "grant restored with new duration"
)

var (
	ErrDuplicateActiveGrant      = errors.New("grant already exists")
	ErrInvalidGrantRestoreParams = errors.New("invalid grant restore parameters")
	ErrInvalidGrantUpdateRequest = errors.New("invalid grant update request")
)

type Grant struct {
	ID                      string      `json:"id" yaml:"id"`
	Status                  GrantStatus `json:"status" yaml:"status"`
	StatusInProvider        GrantStatus `json:"status_in_provider" yaml:"status_in_provider"`
	AccountID               string      `json:"account_id" yaml:"account_id"`
	AccountType             string      `json:"account_type" yaml:"account_type"`
	GroupID                 string      `json:"group_id,omitempty" yaml:"group_id,omitempty"`
	GroupType               string      `json:"group_type,omitempty" yaml:"group_type,omitempty"`
	ResourceID              string      `json:"resource_id" yaml:"resource_id"`
	Role                    string      `json:"role" yaml:"role"`
	Permissions             []string    `json:"permissions" yaml:"permissions"`
	IsPermanent             bool        `json:"is_permanent" yaml:"is_permanent"`
	ExpirationDate          *time.Time  `json:"expiration_date" yaml:"expiration_date"`
	RequestedExpirationDate *time.Time  `json:"requested_expiration_date,omitempty" yaml:"requested_expiration_date,omitempty"`
	ExpirationDateReason    string      `json:"expiration_date_reason,omitempty" yaml:"expiration_date_reason,omitempty"`
	AppealID                string      `json:"appeal_id" yaml:"appeal_id"`
	PendingAppealID         string      `json:"pending_appeal_id" yaml:"pending_appeal_id,omitempty" gorm:"-"`
	Source                  GrantSource `json:"source" yaml:"source"`
	RevokedBy               string      `json:"revoked_by,omitempty" yaml:"revoked_by,omitempty"`
	RevokedAt               *time.Time  `json:"revoked_at,omitempty" yaml:"revoked_at,omitempty"`
	RevokeReason            string      `json:"revoke_reason,omitempty" yaml:"revoke_reason,omitempty"`
	RestoredBy              string      `json:"restored_by,omitempty" yaml:"restored_by,omitempty"`
	RestoredAt              *time.Time  `json:"restored_at,omitempty" yaml:"restored_at,omitempty"`
	RestoreReason           string      `json:"restore_reason,omitempty" yaml:"restore_reason,omitempty"`
	CreatedBy               string      `json:"created_by" yaml:"created_by"` // Deprecated: use Owner instead
	Owner                   string      `json:"owner" yaml:"owner"`
	CreatedAt               time.Time   `json:"created_at" yaml:"created_at"`
	UpdatedAt               time.Time   `json:"updated_at" yaml:"updated_at"`

	Resource   *Resource   `json:"resource,omitempty" yaml:"resource,omitempty"`
	Appeal     *Appeal     `json:"appeal,omitempty" yaml:"appeal,omitempty"`
	Activities []*Activity `json:"activities,omitempty" yaml:"activities,omitempty"`
}

func (g Grant) PermissionsKey() string {
	permissions := make([]string, len(g.Permissions))
	copy(permissions, g.Permissions)
	sort.Strings(permissions)
	return strings.Join(permissions, ";")
}

func (g Grant) IsEligibleForExtension(extensionDurationRule time.Duration) bool {
	if g.ExpirationDate != nil && !g.ExpirationDate.IsZero() {
		return time.Until(*g.ExpirationDate) <= extensionDurationRule
	}
	return true
}

func (g *Grant) Revoke(actor, reason string) error {
	if g == nil {
		return errors.New("grant is nil")
	}
	if actor == "" {
		return errors.New("actor shouldn't be empty")
	}

	g.Status = GrantStatusInactive
	g.RevokedBy = actor
	g.RevokeReason = reason
	now := time.Now()
	g.RevokedAt = &now
	return nil
}

func (g *Grant) Restore(actor, reason string) error {
	if actor == "" {
		return fmt.Errorf("%w: actor is required", ErrInvalidGrantRestoreParams)
	}
	if reason == "" {
		return fmt.Errorf("%w: reason is required", ErrInvalidGrantRestoreParams)
	}

	if g.isExpired() {
		return fmt.Errorf("%w: grant is already expired at: %s", ErrInvalidGrantRestoreParams, g.ExpirationDate)
	}

	g.Status = GrantStatusActive
	g.StatusInProvider = GrantStatusActive

	now := time.Now()
	g.RestoredAt = &now
	g.RestoredBy = actor
	g.RestoreReason = reason
	g.UpdatedAt = now

	return nil
}

func (g *Grant) isExpired() bool {
	return !g.IsPermanent && g.ExpirationDate != nil && time.Now().After(*g.ExpirationDate)
}

func (g *Grant) GetPermissions() []string {
	var permissions []string
	for _, p := range g.Permissions {
		permissions = append(permissions, p)
	}
	return permissions
}

func (g *Grant) Compare(old *Grant, actor string) ([]*DiffItem, error) {
	diff, err := diff.Compare(old, g)
	if err != nil {
		return nil, err
	}

	diffItems := make([]*DiffItem, 0, len(diff))
	for _, d := range diff {
		di := &DiffItem{
			Op:       d.Op,
			Path:     d.Path,
			OldValue: d.OldValue,
			NewValue: d.NewValue,
			Actor:    SystemActorName,
		}
		switch di.Path {
		case "expiration_date", "expiration_date_reason", "is_permanent", "owner":
			di.Actor = actor
		}

		diffItems = append(diffItems, di)
	}
	return diffItems, nil
}

type GrantUpdate struct {
	ID                   string     `json:"id" yaml:"id"`
	Owner                *string    `json:"owner,omitempty" yaml:"owner,omitempty"`
	IsPermanent          *bool      `json:"is_permanent,omitempty" yaml:"is_permanent,omitempty"`
	ExpirationDate       *time.Time `json:"expiration_date,omitempty" yaml:"expiration_date,omitempty"`
	ExpirationDateReason *string    `json:"expiration_date_reason,omitempty" yaml:"expiration_date_reason,omitempty"`

	Actor string `json:"actor" yaml:"actor"`
}

func (gu *GrantUpdate) IsUpdatingExpirationDate() bool {
	return gu.ExpirationDate != nil || gu.ExpirationDateReason != nil
}

func (gu *GrantUpdate) Validate(current Grant) error {
	if gu.ID == "" {
		return errors.New("grant ID is required")
	}
	if current.Status != GrantStatusActive {
		return fmt.Errorf("can't update grant in status %q", current.Status)
	}

	// owner
	if gu.Owner != nil && *gu.Owner == "" {
		return errors.New("owner should not be empty")
	}

	// expiration date
	if gu.IsUpdatingExpirationDate() {
		if gu.ExpirationDate == nil {
			return errors.New("expiration date is required")
		} else if gu.ExpirationDate != nil && gu.ExpirationDate.Before(time.Now()) {
			return errors.New("expiration date can't be in the past")
		} else if current.ExpirationDate != nil && gu.ExpirationDate.After(*current.ExpirationDate) {
			return errors.New("expiration date should be less than existing")
		}

		// expiration date reason
		if gu.ExpirationDateReason == nil || *gu.ExpirationDateReason == "" {
			return errors.New("expiration date reason is required")
		}
	}

	return nil
}

type ListGrantsFilter struct {
	NotIDs                          []string            `json:"not_ids,omitempty"`
	Statuses                        []string            `json:"statuses,omitempty"`
	AccountIDs                      []string            `json:"account_ids,omitempty"`
	AccountTypes                    []string            `json:"account_types,omitempty"`
	GroupIDs                        []string            `json:"group_ids,omitempty"`
	GroupTypes                      []string            `json:"group_types,omitempty"`
	ResourceIDs                     []string            `json:"resource_ids,omitempty"`
	Roles                           []string            `json:"roles,omitempty"`
	Permissions                     []string            `json:"permissions,omitempty"`
	ProviderTypes                   []string            `json:"provider_types,omitempty"`
	ProviderURNs                    []string            `json:"provider_urns,omitempty"`
	ResourceTypes                   []string            `json:"resource_types,omitempty"`
	ResourceURNs                    []string            `json:"resource_urns,omitempty"`
	CreatedBy                       string              `json:"created_by,omitempty"`
	Owner                           string              `json:"owner,omitempty"`
	OrderBy                         []string            `json:"order_by,omitempty"`
	ExpirationDateLessThan          time.Time           `json:"expiration_date_less_than,omitempty"`
	ExpirationDateGreaterThan       time.Time           `json:"expiration_date_greater_than,omitempty"`
	IsPermanent                     *bool               `json:"is_permanent,omitempty"`
	CreatedAtLte                    time.Time           `json:"created_at_lte,omitempty"`
	WithApprovals                   bool                `json:"with_approvals,omitempty"`
	Size                            int                 `json:"size,omitempty" mapstructure:"size" validate:"omitempty"`
	Offset                          int                 `json:"offset,omitempty" mapstructure:"offset" validate:"omitempty"`
	Q                               string              `json:"q,omitempty" mapstructure:"q" validate:"omitempty"`
	StartTime                       time.Time           `json:"start_time,omitempty"`
	EndTime                         time.Time           `json:"end_time,omitempty"`
	SummaryGroupBys                 []string            `json:"summary_group_bys,omitempty"`
	SummaryUniques                  []string            `json:"summary_uniques,omitempty"`
	SummaryDistinctCounts           []string            `json:"summary_distinct_counts,omitempty"`
	ExpiringInDays                  int                 `json:"expiring_in_days,omitempty"`
	FieldMasks                      []string            `json:"field_masks,omitempty"`
	WithPendingAppeal               bool                `json:"with_pending_appeal,omitempty"`
	RoleStartsWith                  string              `json:"role_starts_with,omitempty"`
	RoleEndsWith                    string              `json:"role_ends_with,omitempty"`
	RoleContains                    string              `json:"role_contains,omitempty"`
	Owners                          []string            `json:"owners,omitempty"`
	ProviderUrnStartsWith           string              `json:"provider_urn_starts_with,omitempty"`
	ProviderUrnEndsWith             string              `json:"provider_urn_ends_with,omitempty"`
	ProviderUrnContains             string              `json:"provider_urn_contains,omitempty"`
	ProviderUrnNotStartsWith        string              `json:"provider_urn_not_starts_with,omitempty"`
	ProviderUrnNotEndsWith          string              `json:"provider_urn_not_ends_with,omitempty"`
	ProviderUrnNotContains          string              `json:"provider_urn_not_contains,omitempty"`
	AppealDurations                 []string            `json:"appeal_durations,omitempty"`
	NotAppealDurations              []string            `json:"not_appeal_durations,omitempty"`
	AppealDetailsPaths              []string            `json:"appeal_details_paths,omitempty"`
	AppealDetails                   []string            `json:"appeal_details,omitempty"`
	NotAppealDetails                []string            `json:"not_appeal_details,omitempty"`
	RoleNotStartsWith               string              `json:"role_not_starts_with,omitempty"`
	RoleNotEndsWith                 string              `json:"role_not_ends_with,omitempty"`
	RoleNotContains                 string              `json:"role_not_contains,omitempty"`
	AppealDetailsStartsWith         string              `json:"appeal_details_starts_with,omitempty"`
	AppealDetailsEndsWith           string              `json:"appeal_details_ends_with,omitempty"`
	AppealDetailsContains           string              `json:"appeal_details_contains,omitempty"`
	AppealDetailsNotStartsWith      string              `json:"appeal_details_not_starts_with,omitempty"`
	AppealDetailsNotEndsWith        string              `json:"appeal_details_not_ends_with,omitempty"`
	AppealDetailsNotContains        string              `json:"appeal_details_not_contains,omitempty"`
	GroupTypeStartsWith             string              `json:"group_type_starts_with,omitempty"`
	GroupTypeEndsWith               string              `json:"group_type_ends_with,omitempty"`
	GroupTypeContains               string              `json:"group_type_contains,omitempty"`
	GroupTypeNotStartsWith          string              `json:"group_type_not_starts_with,omitempty"`
	GroupTypeNotEndsWith            string              `json:"group_type_not_ends_with,omitempty"`
	GroupTypeNotContains            string              `json:"group_type_not_contains,omitempty"`
	AppealDetailsForSelfCriteria    []string            `json:"appeal_details_for_self_criteria,omitempty"`
	NotAppealDetailsForSelfCriteria []string            `json:"not_appeal_details_for_self_criteria,omitempty"`
	Labels                          map[string][]string `json:"labels,omitempty"`
	LabelKeys                       []string            `json:"label_keys,omitempty"`
	SummaryLabels                   bool                `json:"summary_labels,omitempty"`
	SummaryLabelsV2                 bool                `json:"summary_labels_v2,omitempty"`
	ExcludeEmptyAppeal              bool                `json:"exclude_empty_appeal,omitempty"`

	UserInactiveGrantPolicy guardianv1beta1.ListUserGrantsRequest_InactiveGrantPolicy `json:"user_inactive_grant_policy,omitempty"`

	InactiveGrantPolicy     guardianv1beta1.ListGrantsRequest_InactiveGrantPolicy `json:"inactive_grant_policy,omitempty"`
	InactiveGrantFilterKeys []string                                              `json:"inactive_grant_filter_keys,omitempty"`
}

func (gf ListGrantsFilter) WithSummary() bool {
	return len(gf.SummaryGroupBys) > 0 || len(gf.SummaryUniques) > 0 || gf.SummaryLabels
}

func (gf ListGrantsFilter) WithGrants() bool {
	return !slices.GenericsSliceContainsOne(gf.FieldMasks, "grants")
}

func (gf ListGrantsFilter) WithTotal() bool {
	return !slices.GenericsSliceContainsOne(gf.FieldMasks, "total")
}

type RevokeGrantsFilter struct {
	AccountIDs    []string `validate:"omitempty,required"`
	ProviderTypes []string `validate:"omitempty,min=1"`
	ProviderURNs  []string `validate:"omitempty,min=1"`
	ResourceTypes []string `validate:"omitempty,min=1"`
	ResourceURNs  []string `validate:"omitempty,min=1"`
}

type AccessEntry struct {
	AccountID   string
	AccountType string
	Permission  string
}

func (ae AccessEntry) ToGrant(resource Resource) Grant {
	g := Grant{
		ResourceID:       resource.ID,
		Status:           GrantStatusActive,
		StatusInProvider: GrantStatusActive,
		AccountID:        ae.AccountID,
		AccountType:      ae.AccountType,
		Role:             ae.Permission,
		Permissions:      []string{ae.Permission},
		Source:           GrantSourceImport,
		IsPermanent:      true,
	}
	if ae.AccountType == "user" {
		g.Owner = ae.AccountID
	}
	return g
}

// MapResourceAccess is list of UserAccess grouped by resource urn
type MapResourceAccess map[string][]AccessEntry

type DormancyCheckCriteria struct {
	ProviderID     string
	Period         time.Duration
	RetainDuration time.Duration
	DryRun         bool
}

func (c DormancyCheckCriteria) Validate() error {
	if c.ProviderID == "" {
		return errors.New("provider id is required")
	}
	if c.Period == 0 {
		return errors.New("period is required")
	} else if c.Period < 0 {
		return errors.New("period must be positive")
	}
	if c.RetainDuration == 0 {
		return errors.New("retain duration is required")
	} else if c.RetainDuration < 0 {
		return errors.New("retain duration must be positive")
	}
	return nil
}
