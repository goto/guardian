package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/lib/pq"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/goto/guardian/core/grant"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/internal/store/postgres/model"
	slicesUtil "github.com/goto/guardian/pkg/slices"
	"github.com/goto/guardian/utils"
)

var (
	GrantStatusDefaultSort = []string{
		string(domain.GrantStatusActive),
		string(domain.GrantStatusInactive),
	}

	grantEntityGroupKeyMapping = map[string]string{
		"grant":    "grants",
		"resource": "Resource",
		"appeal":   "_Appeal",
	}
)

type GrantRepository struct {
	db *gorm.DB
}

func NewGrantRepository(db *gorm.DB) *GrantRepository {
	return &GrantRepository{db}
}

func (r *GrantRepository) List(ctx context.Context, filter domain.ListGrantsFilter) ([]domain.Grant, error) {
	db := r.db.WithContext(ctx)
	db = applyGrantsJoins(db)
	var err error
	db, err = applyGrantsFilter(db, filter)
	if err != nil {
		return nil, err
	}

	var models []model.Grant

	query := db.Preload("Resource")
	// Only preload appeal details if requested
	if filter.WithApprovals {
		query = query.Preload("Appeal").
			Preload("Appeal.Approvals", func(db *gorm.DB) *gorm.DB {
				return db.Order("index ASC")
			}).
			Preload("Appeal.Approvals.Approvers")
	} else {
		query = query.Joins("Appeal")
	}

	if err := query.Find(&models).Error; err != nil {
		return nil, err
	}

	grants := make([]domain.Grant, len(models))
	for i, m := range models {
		g, err := m.ToDomain()
		if err != nil {
			return nil, fmt.Errorf("parsing grant %q: %w", m.ID, err)
		}
		grants[i] = *g
	}

	return grants, nil
}

func (r *GrantRepository) GenerateSummary(ctx context.Context, filter domain.ListGrantsFilter) (*domain.SummaryResult, error) {
	var err error
	if err = utils.ValidateStruct(filter); err != nil {
		return nil, err
	}

	sr := new(domain.SummaryResult)

	dbGen := func() (*gorm.DB, error) {
		// omit offset & size & order_by
		f := filter
		f.Offset = 0
		f.Size = 0
		f.OrderBy = nil

		db := r.db.WithContext(ctx)
		db = applyGrantsJoins(db)
		return applyGrantsFilter(db, f)
	}

	if len(filter.SummaryUniques) > 0 {
		sr.SummaryUniques, err = generateUniqueSummaries(ctx, dbGen, "grants", filter.SummaryUniques, grantEntityGroupKeyMapping)
		if err != nil {
			return nil, err
		}
	}

	if len(filter.SummaryGroupBys) > 0 {
		sr.SummaryGroups, err = generateGroupSummaries(ctx, dbGen, "grants", filter.SummaryGroupBys, filter.SummaryDistinctCounts, grantEntityGroupKeyMapping)
		if err != nil {
			return nil, err
		}
	}

	return generateSummaryResultCount(sr), nil
}

func (r *GrantRepository) GetGrantsTotalCount(ctx context.Context, filter domain.ListGrantsFilter) (int64, error) {
	db := r.db.WithContext(ctx)
	db = applyGrantsJoins(db)

	// omit offset & size & order_by
	f := filter
	f.Size = 0
	f.Offset = 0
	f.OrderBy = nil

	var err error
	db, err = applyGrantsFilter(db, f)
	if err != nil {
		return 0, err
	}
	var count int64
	if err = db.Model(&model.Grant{}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, err
}

func (r *GrantRepository) GetByID(ctx context.Context, id string) (*domain.Grant, error) {
	m := new(model.Grant)
	if err := r.db.WithContext(ctx).Joins("Resource").Joins("Appeal").First(&m, `"grants"."id" = ?`, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, grant.ErrGrantNotFound
		}
		return nil, err
	}

	g, err := m.ToDomain()
	if err != nil {
		return nil, fmt.Errorf("parsing grant %q: %w", g.ID, err)
	}
	return g, nil
}

func (r *GrantRepository) ListUserRoles(ctx context.Context, id string) ([]string, error) {
	db := r.db.WithContext(ctx)
	db = db.Where(`"grants"."owner" = ?`, id)
	db = db.Distinct("role")
	var roles []string
	err := db.Model(&model.Grant{}).Pluck("role", &roles).Error
	return roles, err
}

func (r *GrantRepository) Update(ctx context.Context, a *domain.Grant) error {
	if a == nil || a.ID == "" {
		return grant.ErrEmptyIDParam
	}

	m := new(model.Grant)
	if err := m.FromDomain(*a); err != nil {
		return fmt.Errorf("parsing grant payload: %w", err)
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(m).Updates(*m).Error; err != nil {
			return err
		}

		newGrant, err := m.ToDomain()
		if err != nil {
			return fmt.Errorf("parsing grant: %w", err)
		}
		*a = *newGrant
		return nil
	})
}

func (r *GrantRepository) Patch(ctx context.Context, g domain.GrantUpdate) error {
	if g.ID == "" {
		return grant.ErrEmptyIDParam
	}

	payload := map[string]any{}
	if g.Owner != nil {
		payload["owner"] = *g.Owner
	}
	if g.IsPermanent != nil {
		payload["is_permanent"] = *g.IsPermanent
	}
	if g.ExpirationDate != nil {
		if g.ExpirationDate.IsZero() {
			payload["expiration_date"] = nil
		} else {
			payload["expiration_date"] = *g.ExpirationDate
		}
	}
	if g.ExpirationDateReason != nil {
		payload["expiration_date_reason"] = *g.ExpirationDateReason
	}

	return r.db.
		WithContext(ctx).
		Model(&model.Grant{}).
		Where("id = ?", g.ID).
		Updates(payload).Error
}

func (r *GrantRepository) BulkInsert(ctx context.Context, grants []*domain.Grant) error {
	var models []*model.Grant
	for _, g := range grants {
		m := new(model.Grant)
		if err := m.FromDomain(*g); err != nil {
			return fmt.Errorf("serializing grant: %w", err)
		}
		models = append(models, m)
	}

	if len(models) > 0 {
		return r.db.Transaction(func(tx *gorm.DB) error {
			if err := r.db.Create(models).Error; err != nil {
				return err
			}

			for i, m := range models {
				newGrant, err := m.ToDomain()
				if err != nil {
					return fmt.Errorf("deserializing grant %q: %w", newGrant.ID, err)
				}
				*grants[i] = *newGrant
			}

			return nil
		})
	}

	return nil
}

func (r *GrantRepository) BulkUpsert(ctx context.Context, grants []*domain.Grant) error {
	models := []*model.Grant{}
	for _, g := range grants {
		m := new(model.Grant)
		if err := m.FromDomain(*g); err != nil {
			return fmt.Errorf("serializing grant: %w", err)
		}
		models = append(models, m)
	}

	return r.db.Transaction(func(tx *gorm.DB) error {
		// upsert resources separately to avoid resource upsertion duplicate issue
		if err := upsertResources(tx, models); err != nil {
			return fmt.Errorf("upserting resources: %w", err)
		}
		tx = tx.Omit("Resource")

		if err := tx.
			Clauses(clause.OnConflict{UpdateAll: true}).
			Create(models).
			Error; err != nil {
			return err
		}

		for i, m := range models {
			newGrant, err := m.ToDomain()
			if err != nil {
				return fmt.Errorf("deserializing grant %q: %w", newGrant.ID, err)
			}
			*grants[i] = *newGrant
		}

		return nil
	})
}

func (r *GrantRepository) Create(ctx context.Context, g *domain.Grant) error {
	m := new(model.Grant)
	if err := m.FromDomain(*g); err != nil {
		return err
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(m).Error; err != nil {
			return err
		}

		newGrant, err := m.ToDomain()
		if err != nil {
			return err
		}
		*g = *newGrant

		return nil
	})
}

func upsertResources(tx *gorm.DB, models []*model.Grant) error {
	uniqueResourcesMap := map[string]*model.Resource{}

	for _, m := range models {
		if r := m.Resource; r != nil {
			key := getResourceUniqueURN(*r)
			if _, exists := uniqueResourcesMap[key]; !exists {
				uniqueResourcesMap[key] = r
			} else {
				m.Resource = uniqueResourcesMap[key]
			}
		}
	}

	var resources []*model.Resource
	for _, r := range uniqueResourcesMap {
		resources = append(resources, r)
	}
	if len(resources) > 0 {
		if err := tx.Create(resources).Error; err != nil {
			return fmt.Errorf("failed to upsert resources: %w", err)
		}
	}
	for _, g := range models {
		// set resource id after upsertion
		if g.Resource != nil {
			g.ResourceID = g.Resource.ID.String()
		}
	}

	return nil
}

func applyGrantsJoins(db *gorm.DB) *gorm.DB {
	return db.Joins(`LEFT JOIN "resources" AS "Resource" ON "grants"."resource_id" = "Resource"."id"`).
		Joins(`LEFT JOIN "appeals" AS "_Appeal" ON "grants"."appeal_id" = "_Appeal"."id"`)
}

func applyGrantsFilter(db *gorm.DB, filter domain.ListGrantsFilter) (*gorm.DB, error) {
	var err error

	if filter.Q != "" {
		// NOTE: avoid adding conditions before this grouped where clause.
		// Otherwise, it will be wrapped in parentheses and the query will be invalid.
		db = db.Where(db.
			Where(`"grants"."account_id" LIKE ?`, fmt.Sprintf("%%%s%%", filter.Q)).
			Or(`"grants"."role" LIKE ?`, fmt.Sprintf("%%%s%%", filter.Q)).
			Or(`"Resource"."urn" LIKE ?`, fmt.Sprintf("%%%s%%", filter.Q)).
			Or(`"Resource"."name" LIKE ?`, fmt.Sprintf("%%%s%%", filter.Q)),
		)
	}

	if filter.Size > 0 {
		db = db.Limit(filter.Size)
	}
	if filter.Offset > 0 {
		db = db.Offset(filter.Offset)
	}

	if len(filter.NotIDs) > 0 {
		db = db.Where(`"grants"."id" NOT IN ?`, filter.NotIDs)
	}
	accounts := make([]string, 0)
	if filter.AccountIDs != nil {
		for _, account := range filter.AccountIDs {
			accounts = append(accounts, strings.ToLower(account))
		}
	}
	if len(accounts) > 0 {
		db = db.Where(`LOWER("grants"."account_id") IN ?`, accounts)
	}
	if filter.AccountTypes != nil {
		db = db.Where(`"grants"."account_type" IN ?`, filter.AccountTypes)
	}
	if len(filter.GroupIDs) > 0 {
		db = db.Where(`"grants"."group_id" IN ?`, filter.GroupIDs)
	}
	if filter.ResourceIDs != nil {
		db = db.Where(`"grants"."resource_id" IN ?`, filter.ResourceIDs)
	}
	if filter.Statuses != nil {
		db = db.Where(`"grants"."status" IN ?`, filter.Statuses)
	}
	if filter.Permissions != nil {
		db = db.Where(`"grants"."permissions" @> ?`, pq.StringArray(filter.Permissions))
	}
	owners := filter.Owners
	if filter.Owner != "" {
		owners = append(owners, filter.Owner)
	}
	if filter.CreatedBy != "" {
		owners = append(owners, filter.CreatedBy)
	}
	owners = slicesUtil.GenericsStandardizeSliceNilAble(owners)
	if len(owners) == 1 {
		db = db.Where(`LOWER("grants"."owner") = ?`, owners[0])
	} else if len(owners) > 1 {
		db = db.Where(`LOWER("grants"."owner") IN ?`, owners)
	}
	if filter.IsPermanent != nil {
		db = db.Where(`"grants"."is_permanent" = ?`, *filter.IsPermanent)
	}
	if !filter.CreatedAtLte.IsZero() {
		db = db.Where(`"grants"."created_at" <= ?`, filter.CreatedAtLte)
	}
	if !filter.ExpirationDateLessThan.IsZero() {
		db = db.Where(`"grants"."expiration_date" < ?`, filter.ExpirationDateLessThan)
	}
	if !filter.ExpirationDateGreaterThan.IsZero() {
		db = db.Where(`"grants"."expiration_date" > ?`, filter.ExpirationDateGreaterThan)
	}
	if filter.ProviderTypes != nil {
		db = db.Where(`"Resource"."provider_type" IN ?`, filter.ProviderTypes)
	}
	if filter.ResourceTypes != nil {
		db = db.Where(`"Resource"."type" IN ?`, filter.ResourceTypes)
	}
	if filter.ResourceURNs != nil {
		db = db.Where(`"Resource"."urn" IN ?`, filter.ResourceURNs)
	}
	if filter.ExpiringInDays != 0 && slices.Contains(filter.Statuses, "active") {
		db = db.Where(`"grants"."expiration_date" IS NOT NULL`)
		db = db.Where(fmt.Sprintf(`"grants"."expiration_date" BETWEEN NOW() AND NOW() + INTERVAL '%d day'`, filter.ExpiringInDays))
	}
	if len(filter.AppealDurations) > 0 {
		db = db.Where(`COALESCE(NULLIF("_Appeal"."options" #>> '{duration}', ''), 'null') IN ?`, filter.AppealDurations)
	}
	if len(filter.NotAppealDurations) > 0 {
		db = db.Where(`COALESCE(NULLIF("_Appeal"."options" #>> '{duration}', ''), 'null') NOT IN ?`, filter.NotAppealDurations)
	}

	db, err = applyLikeAndInFilter(db, `"grants"."role"`,
		filter.RoleStartsWith, filter.RoleEndsWith, filter.RoleContains,
		filter.RoleNotStartsWith, filter.RoleNotEndsWith, filter.RoleNotContains,
		filter.Roles, nil, "role",
	)
	if err != nil {
		return nil, err
	}
	db, err = applyLikeAndInFilter(db, `"Resource"."provider_urn"`,
		filter.ProviderUrnStartsWith, filter.ProviderUrnEndsWith, filter.ProviderUrnContains,
		filter.ProviderUrnNotStartsWith, filter.ProviderUrnNotEndsWith, filter.ProviderUrnNotContains,
		filter.ProviderURNs, nil, "provider_urn",
	)
	if err != nil {
		return nil, err
	}
	db, err = applyLikeAndInFilter(db, `"grants"."group_type"`,
		filter.GroupTypeStartsWith, filter.GroupTypeEndsWith, filter.GroupTypeContains,
		filter.GroupTypeNotStartsWith, filter.GroupTypeNotEndsWith, filter.GroupTypeNotContains,
		filter.GroupTypes, nil, "group_type",
	)
	if err != nil {
		return nil, err
	}
	db, err = applyJSONBPathsLikeAndInFilter(db, `"_Appeal"."details"`, filter.AppealDetailsPaths,
		filter.AppealDetailsStartsWith, filter.AppealDetailsEndsWith, filter.AppealDetailsContains,
		filter.AppealDetailsNotStartsWith, filter.AppealDetailsNotEndsWith, filter.AppealDetailsNotContains,
		filter.AppealDetails, filter.NotAppealDetails, "appeal_details",
	)
	if err != nil {
		return nil, err
	}

	if len(filter.AppealDetailsForSelfCriteria) != 0 {
		var exprs []string
		for _, p := range filter.AppealDetailsForSelfCriteria {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			p = strings.ReplaceAll(p, ".", ",")
			exprs = append(exprs, fmt.Sprintf(`"_Appeal"."details" #>> '{%s}'`, p))
		}
		if len(exprs) > 0 {
			db = db.Where(fmt.Sprintf(`"_Appeal"."created_by" = ANY (ARRAY[%s])`, strings.Join(exprs, ",")))
		}
	}
	if len(filter.NotAppealDetailsForSelfCriteria) != 0 {
		var exprs []string
		for _, p := range filter.NotAppealDetailsForSelfCriteria {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			p = strings.ReplaceAll(p, ".", ",")
			exprs = append(exprs, fmt.Sprintf(`COALESCE("_Appeal"."details" #>> '{%s}', '')`, p))
		}
		if len(exprs) > 0 {
			db = db.Where(fmt.Sprintf(`("grants"."appeal_id" IS NULL OR NOT ("_Appeal"."created_by" = ANY (ARRAY[%s])))`, strings.Join(exprs, ",")))
		}
	}

	if !filter.StartTime.IsZero() && !filter.EndTime.IsZero() {
		db = db.Where(`"grants"."created_at" BETWEEN ? AND ?`, filter.StartTime, filter.EndTime)
	} else if !filter.StartTime.IsZero() {
		db = db.Where(`"grants"."created_at" >= ?`, filter.StartTime)
	} else if !filter.EndTime.IsZero() {
		db = db.Where(`"grants"."created_at" <= ?`, filter.EndTime)
	}

	if len(filter.OrderBy) > 0 {
		db, err = addOrderByClause(db, filter.OrderBy, addOrderByClauseOptions{
			statusColumnName: `"grants"."status"`,
			statusesOrder:    GrantStatusDefaultSort,
		}, []string{"updated_at", "created_at"})
		if err != nil {
			return nil, err
		}
	}

	return db, nil
}
