package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/goto/guardian/core/appeal"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/internal/store/postgres/model"
	"github.com/goto/guardian/utils"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
	var err error
	db, err = applyAppealFilter(db, filters)
	if err != nil {
		return nil, err
	}

	var models []*model.Appeal
	if err := db.Joins("Grant").Find(&models).Error; err != nil {
		return nil, err
	}

	records := []*domain.Appeal{}
	for _, m := range models {
		a, err := m.ToDomain()
		if err != nil {
			return nil, fmt.Errorf("parsing appeal: %w", err)
		}

		records = append(records, a)
	}

	return records, nil
}

func (r *AppealRepository) GetAppealsTotalCount(ctx context.Context, filter *domain.ListAppealsFilter) (int64, error) {
	db := r.db.WithContext(ctx)

	appealFilters := *filter
	appealFilters.Size = 0
	appealFilters.Offset = 0

	var err error
	db, err = applyAppealFilter(db, &appealFilters)
	if err != nil {
		return 0, err
	}
	var count int64
	err = db.Model(&model.Appeal{}).Count(&count).Error

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
		if err := tx.Omit("Approvals.Approvers").Session(&gorm.Session{FullSaveAssociations: true}).Save(&m).Error; err != nil {
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

func applyAppealFilter(db *gorm.DB, filters *domain.ListAppealsFilter) (*gorm.DB, error) {
	db = db.Joins("JOIN resources ON appeals.resource_id = resources.id")
	if filters.Q != "" {
		// NOTE: avoid adding conditions before this grouped where clause.
		// Otherwise, it will be wrapped in parentheses and the query will be invalid.
		db = db.Where(db.
			Where(`"appeals"."account_id" LIKE ?`, fmt.Sprintf("%%%s%%", filters.Q)).
			Or(`"appeals"."role" LIKE ?`, fmt.Sprintf("%%%s%%", filters.Q)).
			Or(`"resources"."urn" LIKE ?`, fmt.Sprintf("%%%s%%", filters.Q)).
			Or(`"resources"."name" LIKE ?`, fmt.Sprintf("%%%s%%", filters.Q)),
		)
	}
	if filters.Statuses != nil {
		db = db.Where(`"appeals"."status" IN ?`, filters.Statuses)
	}
	if filters.AccountTypes != nil {
		db = db.Where(`"appeals"."account_type" IN ?`, filters.AccountTypes)
	}
	if filters.ResourceTypes != nil {
		db = db.Where(`"resources"."type" IN ?`, filters.ResourceTypes)
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
	accounts := make([]string, 0)
	if filters.AccountID != "" {
		accounts = append(accounts, strings.ToLower(filters.AccountID))
	}
	if filters.AccountIDs != nil {
		for _, account := range filters.AccountIDs {
			accounts = append(accounts, strings.ToLower(account))
		}
	}
	if len(accounts) > 0 {
		db = db.Where(`LOWER("appeals"."account_id") IN ?`, accounts)
	}
	if filters.Statuses != nil {
		db = db.Where(`"appeals"."status" IN ?`, filters.Statuses)
	}
	if filters.ResourceID != "" {
		db = db.Where(`"appeals"."resource_id" = ?`, filters.ResourceID)
	}
	if filters.Role != "" {
		db = db.Where(`"appeals"."role" = ?`, filters.Role)
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

	db = db.Joins("Resource")
	if filters.ProviderTypes != nil {
		db = db.Where(`"Resource"."provider_type" IN ?`, filters.ProviderTypes)
	}
	if filters.ProviderURNs != nil {
		db = db.Where(`"Resource"."provider_urn" IN ?`, filters.ProviderURNs)
	}
	if filters.ResourceTypes != nil {
		db = db.Where(`"Resource"."type" IN ?`, filters.ResourceTypes)
	}
	if filters.ResourceURNs != nil {
		db = db.Where(`"Resource"."urn" IN ?`, filters.ResourceURNs)
	}

	return db, nil
}
