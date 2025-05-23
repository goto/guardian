package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/goto/guardian/core/grant"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/internal/store/postgres/model"
	"github.com/lib/pq"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	GrantStatusDefaultSort = []string{
		string(domain.GrantStatusActive),
		string(domain.GrantStatusInactive),
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
	var err error
	db, err = applyGrantFilter(db, filter)
	if err != nil {
		return nil, err
	}

	var models []model.Grant
	if err := db.Joins("Resource").Joins("Appeal").Find(&models).Error; err != nil {
		return nil, err
	}

	var grants []domain.Grant
	for _, m := range models {
		g, err := m.ToDomain()
		if err != nil {
			return nil, fmt.Errorf("parsing grant %q: %w", g.ID, err)
		}
		grants = append(grants, *g)
	}

	return grants, nil
}

func (r *GrantRepository) GetGrantsTotalCount(ctx context.Context, filter domain.ListGrantsFilter) (int64, error) {
	db := r.db.WithContext(ctx)

	grantFilters := filter
	grantFilters.Size = 0
	grantFilters.Offset = 0

	var err error
	db, err = applyGrantFilter(db, grantFilters)
	if err != nil {
		return 0, err
	}
	var count int64
	err = db.Model(&model.Grant{}).Count(&count).Error

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

func applyGrantFilter(db *gorm.DB, filter domain.ListGrantsFilter) (*gorm.DB, error) {
	db = db.Joins("JOIN resources ON grants.resource_id = resources.id")
	if filter.Q != "" {
		// NOTE: avoid adding conditions before this grouped where clause.
		// Otherwise, it will be wrapped in parentheses and the query will be invalid.
		db = db.Where(db.
			Where(`"grants"."account_id" LIKE ?`, fmt.Sprintf("%%%s%%", filter.Q)).
			Or(`"grants"."role" LIKE ?`, fmt.Sprintf("%%%s%%", filter.Q)).
			Or(`"resources"."urn" LIKE ?`, fmt.Sprintf("%%%s%%", filter.Q)).
			Or(`"resources"."name" LIKE ?`, fmt.Sprintf("%%%s%%", filter.Q)),
		)
	}

	if filter.Size > 0 {
		db = db.Limit(filter.Size)
	}
	if filter.Offset > 0 {
		db = db.Offset(filter.Offset)
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
	if filter.ResourceIDs != nil {
		db = db.Where(`"grants"."resource_id" IN ?`, filter.ResourceIDs)
	}
	if filter.Statuses != nil {
		db = db.Where(`"grants"."status" IN ?`, filter.Statuses)
	}
	if filter.Roles != nil {
		db = db.Where(`"grants"."role" IN ?`, filter.Roles)
	}
	if filter.Permissions != nil {
		db = db.Where(`"grants"."permissions" @> ?`, pq.StringArray(filter.Permissions))
	}
	if filter.Owner != "" {
		db = db.Where(`LOWER("grants"."owner") = ?`, strings.ToLower(filter.Owner))
	} else if filter.CreatedBy != "" {
		db = db.Where(`LOWER("grants"."owner") = ?`, strings.ToLower(filter.CreatedBy))
	}
	if filter.IsPermanent != nil {
		db = db.Where(`"grants"."is_permanent" = ?`, *filter.IsPermanent)
	}
	if !filter.CreatedAtLte.IsZero() {
		db = db.Where(`"grants"."created_at" <= ?`, filter.CreatedAtLte)
	}
	if filter.OrderBy != nil {
		var err error
		db, err = addOrderByClause(db, filter.OrderBy, addOrderByClauseOptions{
			statusColumnName: `"grants"."status"`,
			statusesOrder:    GrantStatusDefaultSort,
		},
			[]string{"updated_at", "created_at"})

		if err != nil {
			return nil, err
		}
	}
	if !filter.ExpirationDateLessThan.IsZero() {
		db = db.Where(`"grants"."expiration_date" < ?`, filter.ExpirationDateLessThan)
	}
	if !filter.ExpirationDateGreaterThan.IsZero() {
		db = db.Where(`"grants"."expiration_date" > ?`, filter.ExpirationDateGreaterThan)
	}
	db = db.Joins("Resource")
	if filter.ProviderTypes != nil {
		db = db.Where(`"Resource"."provider_type" IN ?`, filter.ProviderTypes)
	}
	if filter.ProviderURNs != nil {
		db = db.Where(`"Resource"."provider_urn" IN ?`, filter.ProviderURNs)
	}
	if filter.ResourceTypes != nil {
		db = db.Where(`"Resource"."type" IN ?`, filter.ResourceTypes)
	}
	if filter.ResourceURNs != nil {
		db = db.Where(`"Resource"."urn" IN ?`, filter.ResourceURNs)
	}
	return db, nil
}
