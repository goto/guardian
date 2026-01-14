package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lib/pq"
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

	dbGen := func() (*gorm.DB, error) {
		// omit offset & size & order_by
		f := filters
		f.Offset = 0
		f.Size = 0
		f.OrderBy = nil

		db := r.db.WithContext(ctx)
		db = applyAppealsJoins(db)
		return applyAppealsFilter(db, f)
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

	roles := slicesUtil.GenericsUniqueSliceValues(filters.Roles)
	if filters.Role != "" {
		roles = slicesUtil.GenericsUniqueSliceValues(append(roles, filters.Role))
	}
	if len(roles) != 0 {
		db = db.Where(`LOWER("appeals"."role") IN ?`, roles)
	}

	if len(filters.GroupIDs) > 0 {
		db = db.Where(`"appeals"."group_id" IN ?`, filters.GroupIDs)
	}
	if len(filters.GroupTypes) > 0 {
		db = db.Where(`"appeals"."group_type" IN ?`, filters.GroupTypes)
	}
	if !filters.ExpirationDateLessThan.IsZero() {
		db = db.Where(`"options" -> 'expiration_date' < ?`, filters.ExpirationDateLessThan)
	}
	if !filters.ExpirationDateGreaterThan.IsZero() {
		db = db.Where(`"options" -> 'expiration_date' > ?`, filters.ExpirationDateGreaterThan)
	}
	if filters.OrderBy != nil {
		var err error
		db, err = addOrderByClause(db, filters.OrderBy, addOrderByClauseOptions{
			statusColumnName: `"appeals"."status"`,
			statusesOrder:    AppealStatusDefaultSort,
		},
			[]string{"updated_at", "created_at"})

		if err != nil {
			return nil, err
		}
	}

	if filters.ProviderTypes != nil {
		db = db.Where(`"Resource"."provider_type" IN ?`, filters.ProviderTypes)
	}
	if filters.ResourceURNs != nil {
		db = db.Where(`"Resource"."urn" IN ?`, filters.ResourceURNs)
	}

	var rolePatterns []string
	if filters.RoleStartsWith != "" {
		rolePatterns = append(rolePatterns, filters.RoleStartsWith+"%")
	}
	if filters.RoleEndsWith != "" {
		rolePatterns = append(rolePatterns, "%"+filters.RoleEndsWith)
	}
	if filters.RoleContains != "" {
		rolePatterns = append(rolePatterns, "%"+filters.RoleContains+"%")
	}
	if len(filters.Roles) > 0 {
		rolePatterns = append(rolePatterns, filters.Roles...)
	}
	rolePatterns = slicesUtil.GenericsStandardizeSlice(rolePatterns)
	if len(rolePatterns) > 0 {
		db = db.Where(`LOWER("appeals"."role") LIKE ANY (?)`, pq.Array(rolePatterns))
	}

	if (filters.ProviderUrnStartsWith != "" || filters.ProviderUrnEndsWith != "") && filters.ProviderUrnContains != "" {
		return nil, fmt.Errorf("invalid filter: provider_urn_contains cannot be used together with provider_urn_starts_with or provider_urn_ends_with")
	}
	var providerUrnPatterns []string
	if filters.ProviderUrnStartsWith != "" {
		providerUrnPatterns = append(providerUrnPatterns, filters.ProviderUrnStartsWith+"%")
	}
	if filters.ProviderUrnEndsWith != "" {
		providerUrnPatterns = append(providerUrnPatterns, "%"+filters.ProviderUrnEndsWith)
	}
	if filters.ProviderUrnContains != "" {
		providerUrnPatterns = append(providerUrnPatterns, "%"+filters.ProviderUrnContains+"%")
	}
	if len(filters.ProviderURNs) > 0 {
		providerUrnPatterns = append(providerUrnPatterns, filters.ProviderURNs...)
	}
	providerUrnPatterns = slicesUtil.GenericsStandardizeSlice(providerUrnPatterns)
	if len(providerUrnPatterns) > 0 {
		db = db.Where(`"Resource"."provider_urn" LIKE ANY (?)`, pq.Array(providerUrnPatterns))
	}

	if (filters.ProviderUrnNotStartsWith != "" || filters.ProviderUrnNotEndsWith != "") && filters.ProviderUrnNotContains != "" {
		return nil, fmt.Errorf("invalid filter: provider_urn_not_contains cannot be used together with provider_urn_not_starts_with or provider_urn_not_ends_with")
	}
	var providerUrnNotPatterns []string
	if filters.ProviderUrnNotStartsWith != "" {
		providerUrnNotPatterns = append(providerUrnNotPatterns, filters.ProviderUrnNotStartsWith+"%")
	}
	if filters.ProviderUrnNotEndsWith != "" {
		providerUrnNotPatterns = append(providerUrnNotPatterns, "%"+filters.ProviderUrnNotEndsWith)
	}
	if filters.ProviderUrnNotContains != "" {
		providerUrnNotPatterns = append(providerUrnNotPatterns, "%"+filters.ProviderUrnNotContains+"%")
	}
	providerUrnNotPatterns = slicesUtil.GenericsStandardizeSlice(providerUrnNotPatterns)
	if len(providerUrnNotPatterns) > 0 {
		db = db.Where(`"Resource"."provider_urn" NOT LIKE ANY (?)`, pq.Array(providerUrnNotPatterns))
	}

	if len(filters.Durations) > 0 {
		db = db.Where(`"appeals"."options" #>> '{duration}' IN ?`, filters.Durations)
	}
	if len(filters.NotDurations) > 0 {
		db = db.Where(`"appeals"."options" #>> '{duration}' NOT IN ?`, filters.NotDurations)
	}

	for _, detailsPath := range filters.DetailsPaths {
		detailsPath = strings.TrimSpace(detailsPath)
		if len(detailsPath) == 0 {
			continue
		}
		detailsPath = strings.ReplaceAll(detailsPath, ".", ",")
		if len(filters.Details) > 0 {
			db = db.Where(fmt.Sprintf(`"appeals"."details" #>> '{%s}' IN ?`, detailsPath), filters.Durations)
		}
		if len(filters.NotDetails) > 0 {
			db = db.Where(fmt.Sprintf(`"appeals"."details" #>> '{%s}' NOT IN ?`, detailsPath), filters.Durations)
		}
	}

	if !filters.StartTime.IsZero() && !filters.EndTime.IsZero() {
		db = db.Where(`"appeals"."created_at" BETWEEN ? AND ?`, filters.StartTime, filters.EndTime)
	} else if !filters.StartTime.IsZero() {
		db = db.Where(`"appeals"."created_at" >= ?`, filters.StartTime)
	} else if !filters.EndTime.IsZero() {
		db = db.Where(`"appeals"."created_at" <= ?`, filters.EndTime)
	}

	if filters.WithApprovals {
		db = db.Preload("Approvals")
		db = db.Preload("Approvals.Approvers")
	}

	// Label filtering
	if len(filters.Labels) > 0 {
		db = applyLabelFilters(db, filters.Labels)
	}

	if len(filters.LabelKeys) > 0 {
		db = applyLabelKeyFilters(db, filters.LabelKeys)
	}

	return db, nil
}

// applyLabelFilters applies label key-value filtering with OR logic for multiple values
func applyLabelFilters(db *gorm.DB, labels map[string][]string) *gorm.DB {
	for key, values := range labels {
		if len(values) == 0 {
			continue
		}

		// Filter using PostgreSQL JSONB operators
		// labels->>key checks if the key exists and returns its value
		if len(values) == 1 {
			db = db.Where(`"appeals"."labels"->>? = ?`, key, values[0])
		} else {
			// OR logic for multiple values for the same key
			db = db.Where(`"appeals"."labels"->>? IN ?`, key, values)
		}
	}
	return db
}

// applyLabelKeyFilters applies filtering by label keys (regardless of value) with OR logic
func applyLabelKeyFilters(db *gorm.DB, keys []string) *gorm.DB {
	if len(keys) == 0 {
		return db
	}

	// Build OR condition for checking if any of the keys exist
	// labels ? 'key' checks if the key exists in the JSONB object
	var orConditions []string
	var params []interface{}

	for _, key := range keys {
		orConditions = append(orConditions, `"appeals"."labels" ? ?`)
		params = append(params, key)
	}

	query := strings.Join(orConditions, " OR ")
	db = db.Where(query, params...)

	return db
}
