package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/lib/pq"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/goto/guardian/core/appeal"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/internal/store/postgres/model"
	slicesUtil "github.com/goto/guardian/pkg/slices"
	"github.com/goto/guardian/utils"
)

const (
	pgUniqueViolationErrorCode = "23505"
	grantUniqueConstraintName  = "unique_active_grants_index"
)

var (
	AppealStatusDefaultSort = []string{
		domain.AppealStatusPending,
		domain.AppealStatusApproved,
		domain.AppealStatusRejected,
		domain.AppealStatusCanceled,
	}

	appealEntityGroupKeyMapping = map[string]string{
		"appeal":   "appeals",
		"resource": "Resource",
	}
)

// AppealRepository talks to the store to read or insert data
type AppealRepository struct {
	db *gorm.DB
}

// NewAppealRepository returns repository struct
func NewAppealRepository(db *gorm.DB) *AppealRepository {
	return &AppealRepository{db}
}

// GetByID returns appeal record by id along with the approvals and the approvers
func (r *AppealRepository) GetByID(ctx context.Context, id string) (*domain.Appeal, error) {
	m := new(model.Appeal)
	if err := r.db.
		WithContext(ctx).
		Preload("Approvals", func(db *gorm.DB) *gorm.DB {
			return db.Order("Approvals.index ASC")
		}).
		Preload("Approvals.Approvers").
		Preload("Resource").
		Preload("Grant").
		First(&m, "id = ?", id).
		Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, appeal.ErrAppealNotFound
		}
		return nil, err
	}

	a, err := m.ToDomain()
	if err != nil {
		return nil, fmt.Errorf("parsing appeal: %w", err)
	}

	return a, nil
}

func (r *AppealRepository) Find(ctx context.Context, filters *domain.ListAppealsFilter) ([]*domain.Appeal, error) {
	if err := utils.ValidateStruct(filters); err != nil {
		return nil, err
	}

	db := r.db.WithContext(ctx)
	db = applyAppealsJoins(db)
	var err error
	db, err = applyAppealsFilter(db, filters)
	if err != nil {
		return nil, err
	}

	var models []*model.Appeal
	if err := db.Preload("Resource").
		Preload("Grant").
		Find(&models).Error; err != nil {
		return nil, err
	}

	records := make([]*domain.Appeal, len(models))
	for i, m := range models {
		a, err := m.ToDomain()
		if err != nil {
			return nil, fmt.Errorf("parsing appeal: %w", err)
		}
		records[i] = a
	}

	return records, nil
}

func (r *AppealRepository) GenerateSummary(ctx context.Context, filters *domain.ListAppealsFilter) (*domain.SummaryResult, error) {
	var err error
	if err = utils.ValidateStruct(filters); err != nil {
		return nil, err
	}

	sr := new(domain.SummaryResult)

	dbGen := func(gCtx context.Context) (*gorm.DB, error) {
		// omit offset & size & order_by
		f := *filters
		f.Offset = 0
		f.Size = 0
		f.OrderBy = nil

		db := r.db.WithContext(gCtx)
		db = applyAppealsJoins(db)
		return applyAppealsFilter(db, &f)
	}

	if filters.SummaryLabels {
		sr.SummaryLabels, err = generateLabelSummaries(ctx, dbGen, "appeals", `"appeals"."labels"`)
		if err != nil {
			return nil, err
		}
	}

	if len(filters.SummaryUniques) > 0 {
		sr.SummaryUniques, err = generateUniqueSummaries(ctx, dbGen, "appeals", filters.SummaryUniques, appealEntityGroupKeyMapping)
		if err != nil {
			return nil, err
		}
	}

	if len(filters.SummaryGroupBys) > 0 {
		sr.SummaryGroups, err = generateGroupSummaries(ctx, dbGen, "appeals", filters.SummaryGroupBys, nil, appealEntityGroupKeyMapping)
		if err != nil {
			return nil, err
		}
	}

	return generateSummaryResultCount(sr), nil
}

func (r *AppealRepository) GetAppealsTotalCount(ctx context.Context, filter *domain.ListAppealsFilter) (int64, error) {
	db := r.db.WithContext(ctx)
	db = applyAppealsJoins(db)

	// omit offset & size & order_by & with_approvals
	f := *filter
	f.Size = 0
	f.Offset = 0
	f.OrderBy = nil
	f.WithApprovals = false

	var err error
	db, err = applyAppealsFilter(db, &f)
	if err != nil {
		return 0, err
	}
	var count int64
	if err = db.Model(&model.Appeal{}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, err
}

// BulkUpsert new record to database
func (r *AppealRepository) BulkUpsert(ctx context.Context, appeals []*domain.Appeal) error {
	models := []*model.Appeal{}
	for _, a := range appeals {
		m := new(model.Appeal)
		if err := m.FromDomain(a); err != nil {
			return err
		}
		models = append(models, m)
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.
			Clauses(clause.OnConflict{UpdateAll: true}).
			Create(models).
			Error; err != nil {
			return err
		}

		for i, m := range models {
			newAppeal, err := m.ToDomain()
			if err != nil {
				return fmt.Errorf("parsing appeal: %w", err)
			}

			*appeals[i] = *newAppeal
		}

		return nil
	})
}

func (r *AppealRepository) UpdateByID(ctx context.Context, a *domain.Appeal) error {
	if a.ID == "" {
		return appeal.ErrAppealIDEmptyParam
	}

	m := new(model.Appeal)
	if err := m.FromDomain(a); err != nil {
		return err
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(m).Session(&gorm.Session{FullSaveAssociations: true}).Where(`"id" = ?`, a.ID).Updates(*m).Error; err != nil {
			var pgError *pgconn.PgError
			if errors.As(err, &pgError) && pgError.Code == pgUniqueViolationErrorCode && pgError.ConstraintName == grantUniqueConstraintName {
				return domain.ErrDuplicateActiveGrant
			}
			return err
		}

		newRecord, err := m.ToDomain()
		if err != nil {
			return err
		}

		*a = *newRecord

		return nil
	})
}

// Update an approval step
func (r *AppealRepository) Update(ctx context.Context, a *domain.Appeal) error {
	m := new(model.Appeal)
	if err := m.FromDomain(a); err != nil {
		return err
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Omit("Approvals.Approvers", "Resource", "Grant.Resource").Session(&gorm.Session{FullSaveAssociations: true}).Save(&m).Error; err != nil {
			var pgError *pgconn.PgError
			if errors.As(err, &pgError) && pgError.Code == pgUniqueViolationErrorCode && pgError.ConstraintName == grantUniqueConstraintName {
				return domain.ErrDuplicateActiveGrant
			}
			return err
		}

		newRecord, err := m.ToDomain()
		if err != nil {
			return fmt.Errorf("parsing appeal: %w", err)
		}

		*a = *newRecord

		return nil
	})
}

func applyAppealsJoins(db *gorm.DB) *gorm.DB {
	return db.Joins(`LEFT JOIN "resources" AS "Resource" ON "appeals"."resource_id" = "Resource"."id"`)
}

func applyAppealsFilter(db *gorm.DB, filters *domain.ListAppealsFilter) (*gorm.DB, error) {
	var err error

	if filters.Q != "" {
		// NOTE: avoid adding conditions before this grouped where clause.
		// Otherwise, it will be wrapped in parentheses and the query will be invalid.
		db = db.Where(db.
			Where(`"appeals"."account_id" LIKE ?`, fmt.Sprintf("%%%s%%", filters.Q)).
			Or(`"appeals"."role" LIKE ?`, fmt.Sprintf("%%%s%%", filters.Q)).
			Or(`"Resource"."urn" LIKE ?`, fmt.Sprintf("%%%s%%", filters.Q)).
			Or(`"Resource"."name" LIKE ?`, fmt.Sprintf("%%%s%%", filters.Q)),
		)
	}

	if filters.IDs != nil {
		db = db.Where(`"appeals"."id" IN ?`, filters.IDs)
	}

	if filters.NotIDs != nil {
		db = db.Where(`"appeals"."id" NOT IN ?`, filters.NotIDs)
	}

	if filters.Statuses != nil {
		db = db.Where(`"appeals"."status" IN ?`, filters.Statuses)
	}
	if filters.AccountTypes != nil {
		db = db.Where(`"appeals"."account_type" IN ?`, filters.AccountTypes)
	}
	if filters.ResourceTypes != nil {
		db = db.Where(`"Resource"."type" IN ?`, filters.ResourceTypes)
	}
	if filters.Size > 0 {
		db = db.Limit(filters.Size)
	}
	if filters.Offset > 0 {
		db = db.Offset(filters.Offset)
	}
	if filters.CreatedBy != "" {
		db = db.Where(`LOWER("appeals"."created_by") = ?`, strings.ToLower(filters.CreatedBy))
	}
	if filters.Statuses != nil {
		db = db.Where(`"appeals"."status" IN ?`, filters.Statuses)
	}
	accountIDs := slicesUtil.GenericsUniqueSliceValues(filters.AccountIDs)
	if filters.AccountID != "" {
		accountIDs = slicesUtil.GenericsUniqueSliceValues(append(accountIDs, filters.AccountID))
	}
	if len(accountIDs) > 0 {
		db = db.Where(`LOWER("appeals"."account_id") IN ?`, slicesUtil.ToLowerStringSlice(accountIDs))
	}
	resourceIDs := slicesUtil.GenericsUniqueSliceValues(filters.ResourceIDs)
	if filters.ResourceID != "" {
		resourceIDs = slicesUtil.GenericsUniqueSliceValues(append(resourceIDs, filters.ResourceID))
	}
	if len(resourceIDs) != 0 {
		db = db.Where(`"appeals"."resource_id" IN ?`, resourceIDs)
	}
	if len(filters.GroupIDs) > 0 {
		db = db.Where(`"appeals"."group_id" IN ?`, filters.GroupIDs)
	}
	if !filters.ExpirationDateLessThan.IsZero() {
		db = db.Where(`"options" -> 'expiration_date' < ?`, filters.ExpirationDateLessThan)
	}
	if !filters.ExpirationDateGreaterThan.IsZero() {
		db = db.Where(`"options" -> 'expiration_date' > ?`, filters.ExpirationDateGreaterThan)
	}
	if filters.ProviderTypes != nil {
		db = db.Where(`"Resource"."provider_type" IN ?`, filters.ProviderTypes)
	}
	if filters.ResourceURNs != nil {
		db = db.Where(`"Resource"."urn" IN ?`, filters.ResourceURNs)
	}
	if len(filters.Durations) > 0 {
		db = db.Where(`COALESCE(NULLIF("appeals"."options" #>> '{duration}', ''), 'null') IN ?`, filters.Durations)
	}
	if len(filters.NotDurations) > 0 {
		db = db.Where(`COALESCE(NULLIF("appeals"."options" #>> '{duration}', ''), 'null') NOT IN ?`, filters.NotDurations)
	}

	db, err = applyLikeAndInFilter(db, `LOWER("appeals"."role")`,
		filters.RoleStartsWith, filters.RoleEndsWith, filters.RoleContains,
		filters.RoleNotStartsWith, filters.RoleNotEndsWith, filters.RoleNotContains,
		filters.Roles, nil, "role",
	)
	if err != nil {
		return nil, err
	}
	db, err = applyLikeAndInFilter(db, `"Resource"."provider_urn"`,
		filters.ProviderUrnStartsWith, filters.ProviderUrnEndsWith, filters.ProviderUrnContains,
		filters.ProviderUrnNotStartsWith, filters.ProviderUrnNotEndsWith, filters.ProviderUrnNotContains,
		filters.ProviderURNs, nil, "provider_urn",
	)
	if err != nil {
		return nil, err
	}
	db, err = applyLikeAndInFilter(db, `"appeals"."group_type"`,
		filters.GroupTypeStartsWith, filters.GroupTypeEndsWith, filters.GroupTypeContains,
		filters.GroupTypeNotStartsWith, filters.GroupTypeNotEndsWith, filters.GroupTypeNotContains,
		filters.GroupTypes, nil, "group_type",
	)
	if err != nil {
		return nil, err
	}
	db, err = applyJSONBPathsLikeAndInFilter(db, `"appeals"."details"`, filters.DetailsPaths,
		filters.DetailsStartsWith, filters.DetailsEndsWith, filters.DetailsContains,
		filters.DetailsNotStartsWith, filters.DetailsNotEndsWith, filters.DetailsNotContains,
		filters.Details, filters.NotDetails, "details",
	)
	if err != nil {
		return nil, err
	}

	if len(filters.DetailsForSelfCriteria) != 0 && len(filters.NotDetailsForSelfCriteria) != 0 {
		return nil, fmt.Errorf("cannot use both details_for_self_criteria and not_details_for_self_criteria filters")
	}
	if len(filters.DetailsForSelfCriteria) != 0 {
		var exprs []string
		for _, p := range filters.DetailsForSelfCriteria {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			p = strings.ReplaceAll(p, ".", ",")
			exprs = append(exprs, fmt.Sprintf(`"appeals"."details" #>> '{%s}'`, p))
		}
		if len(exprs) > 0 {
			db = db.Where(fmt.Sprintf(`"appeals"."created_by" = ANY (ARRAY[%s])`, strings.Join(exprs, ",")))
		}
	}
	if len(filters.NotDetailsForSelfCriteria) != 0 {
		var exprs []string
		for _, p := range filters.NotDetailsForSelfCriteria {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			p = strings.ReplaceAll(p, ".", ",")
			exprs = append(exprs, fmt.Sprintf(`COALESCE("appeals"."details" #>> '{%s}', '')`, p))
		}
		if len(exprs) > 0 {
			db = db.Where(fmt.Sprintf(`NOT ("appeals"."created_by" = ANY (ARRAY[%s]))`, strings.Join(exprs, ",")))
		}
	}

	if !filters.StartTime.IsZero() && !filters.EndTime.IsZero() {
		db = db.Where(`"appeals"."created_at" BETWEEN ? AND ?`, filters.StartTime, filters.EndTime)
	} else if !filters.StartTime.IsZero() {
		db = db.Where(`"appeals"."created_at" >= ?`, filters.StartTime)
	} else if !filters.EndTime.IsZero() {
		db = db.Where(`"appeals"."created_at" <= ?`, filters.EndTime)
	}

	if filters.OrderBy != nil {
		db, err = addOrderByClause(db, filters.OrderBy, addOrderByClauseOptions{
			statusColumnName: `"appeals"."status"`,
			statusesOrder:    AppealStatusDefaultSort,
		}, []string{"updated_at", "created_at"})
		if err != nil {
			return nil, err
		}
	}

	if filters.WithApprovals {
		db = db.Preload("Approvals")
		db = db.Preload("Approvals.Approvers")
	}

	// Label filtering
	if len(filters.Labels) > 0 {
		db = applyLabelFilter(db, `"appeals"."labels"`, filters.Labels)
	}

	if len(filters.LabelKeys) > 0 {
		db = applyLabelKeyFilter(db, `"appeals"."labels"`, filters.LabelKeys)
	}

	return db, nil
}

// UpdateLabels updates only the labels and label metadata of an appeal
func (r *AppealRepository) UpdateLabels(ctx context.Context, a *domain.Appeal) error {
	if a.ID == "" {
		return appeal.ErrAppealIDEmptyParam
	}

	m := new(model.Appeal)
	if err := m.FromDomain(a); err != nil {
		return err
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.Appeal{}).
			Where("id = ?", a.ID).
			Select("labels", "labels_metadata").
			Updates(m).Error; err != nil {
			return err
		}

		// Reload to get updated timestamps and state
		if err := tx.Where("id = ?", a.ID).First(m).Error; err != nil {
			return err
		}

		newRecord, err := m.ToDomain()
		if err != nil {
			return err
		}

		*a = *newRecord
		return nil
	})
}
