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
	NotIDs                    []string
	Statuses                  []string
	AccountIDs                []string
	AccountTypes              []string
	GroupIDs                  []string
	GroupTypes                []string
	ResourceIDs               []string
	Roles                     []string
	Permissions               []string
	ProviderTypes             []string
	ProviderURNs              []string
	ResourceTypes             []string
	ResourceURNs              []string
	CreatedBy                 string
	Owner                     string
	OrderBy                   []string
	ExpirationDateLessThan    time.Time
	ExpirationDateGreaterThan time.Time
	IsPermanent               *bool
	CreatedAtLte              time.Time
	WithApprovals             bool
	Size                      int    `mapstructure:"size" validate:"omitempty"`
	Offset                    int    `mapstructure:"offset" validate:"omitempty"`
	Q                         string `mapstructure:"q" validate:"omitempty"`
	StartTime                 time.Time
	EndTime                   time.Time
	SummaryGroupBys           []string
	SummaryUniques            []string
	SummaryDistinctCounts     []string
	ExpiringInDays            int
	FieldMasks                []string
	WithPendingAppeal         bool
	RoleStartsWith            string
	RoleEndsWith              string
	RoleContains              string
	CreatedBys                []string

	UserInactiveGrantPolicy guardianv1beta1.ListUserGrantsRequest_InactiveGrantPolicy
}

func (gf ListGrantsFilter) WithSummary() bool {
	return len(gf.SummaryGroupBys) > 0 || len(gf.SummaryUniques) > 0
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
