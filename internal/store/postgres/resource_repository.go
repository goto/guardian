package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/goto/guardian/core/resource"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/internal/store/postgres/model"
	"github.com/goto/guardian/utils"
	"gorm.io/gorm"
)

var (
	resourcesDefaultSort = []string{
		"created_at:desc",
	}
)

// ResourceRepository talks to the store/database to read/insert data
type ResourceRepository struct {
	db *gorm.DB
}

// NewResourceRepository returns *Repository
func NewResourceRepository(db *gorm.DB) *ResourceRepository {
	return &ResourceRepository{db}
}

// Find records based on filters
func (r *ResourceRepository) Find(ctx context.Context, filter domain.ListResourcesFilter) ([]*domain.Resource, error) {
	if err := utils.ValidateStruct(filter); err != nil {
		return nil, err
	}

	db := r.db.WithContext(ctx)
	var err error
	db, err = applyResourceFilter(db, filter)
	if err != nil {
		return nil, err
	}
	var models []*model.Resource
	if err := db.Find(&models).Error; err != nil {
		return nil, err
	}

	records := []*domain.Resource{}
	for _, m := range models {
		r, err := m.ToDomain()
		if err != nil {
			return nil, err
		}

		records = append(records, r)
	}

	return records, nil
}

func (r *ResourceRepository) GetResourcesTotalCount(ctx context.Context, filter domain.ListResourcesFilter) (int64, error) {
	db := r.db.WithContext(ctx)

	f := filter
	f.Size = 0
	f.Offset = 0
	var err error
	db, err = applyResourceFilter(db, f)
	if err != nil {
		return 0, err
	}
	var count int64
	err = db.Model(&model.Resource{}).Count(&count).Error

	return count, err
}

func applyResourceFilter(db *gorm.DB, filter domain.ListResourcesFilter) (*gorm.DB, error) {
	if filter.Q != "" {
		// NOTE: avoid adding conditions before this grouped where clause.
		// Otherwise, it will be wrapped in parentheses and the query will be invalid.
		db = db.Where(db.
			Where(`"urn" ILIKE ?`, fmt.Sprintf("%%%s%%", filter.Q)).
			Or(`"name" ILIKE ?`, fmt.Sprintf("%%%s%%", filter.Q)).
			Or(`"global_urn" ILIKE ?`, fmt.Sprintf("%%%s%%", filter.Q)),
		)
	}
	if filter.IDs != nil {
		db = db.Where(filter.IDs)
	}
	if !filter.IsDeleted {
		db = db.Where(`"is_deleted" = ?`, filter.IsDeleted)
	}
	if filter.ResourceType != "" {
		db = db.Where(`"type" = ?`, filter.ResourceType)
	}
	if filter.Name != "" {
		db = db.Where(`"name" = ?`, filter.Name)
	}
	if filter.ProviderType != "" {
		db = db.Where(`"provider_type" = ?`, filter.ProviderType)
	}
	if filter.ProviderURN != "" {
		db = db.Where(`"provider_urn" = ?`, filter.ProviderURN)
	}
	if filter.ResourceURN != "" {
		db = db.Where(`"urn" = ?`, filter.ResourceURN)
	}
	if filter.ResourceURNs != nil {
		db = db.Where(`"urn" IN ?`, filter.ResourceURNs)
	}
	if filter.ResourceTypes != nil {
		db = db.Where(`"type" IN ?`, filter.ResourceTypes)
	}

	if filter.Size > 0 {
		db = db.Limit(int(filter.Size))
	}

	if filter.Offset > 0 {
		db = db.Offset(int(filter.Offset))
	}

	var sortOrder []string

	if filter.Offset >= 0 {
		sortOrder = resourcesDefaultSort
	}

	if filter.OrderBy != nil {
		sortOrder = filter.OrderBy
	}

	if len(sortOrder) != 0 {
		var err error
		db, err = addOrderByClause(db, sortOrder, addOrderByClauseOptions{
			statusColumnName: "",
			statusesOrder:    []string{},
			searchQuery:      filter.Q,
		},
			[]string{"updated_at", "created_at", "name", "urn", "global_urn"})

		if err != nil {
			return nil, err
		}
	}

	for path, v := range filter.Details {
		pathArr := "{" + strings.Join(strings.Split(path, "."), ",") + "}"
		db = db.Where(`"details" #>> ? = ?`, pathArr, v)
	}
	return db, nil
}

// GetOne record by ID
func (r *ResourceRepository) GetOne(ctx context.Context, id string) (*domain.Resource, error) {
	if id == "" {
		return nil, resource.ErrEmptyIDParam
	}

	whereClause := `"id" = ?`
	if _, err := uuid.Parse(id); err != nil {
		whereClause = `"global_urn" = ?`
	}

	var m model.Resource
	if err := r.db.WithContext(ctx).Where(whereClause, id).Take(&m).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, resource.ErrRecordNotFound
		}
		return nil, err
	}

	res, err := m.ToDomain()
	if err != nil {
		return nil, err
	}

	return res, nil
}

// BulkUpsert inserts records if the records are not exist, or updates the records if they are already exist
func (r *ResourceRepository) BulkUpsert(ctx context.Context, resources []*domain.Resource) error {
	var models []*model.Resource
	for _, r := range resources {
		m := new(model.Resource)
		if err := m.FromDomain(r); err != nil {
			return err
		}

		models = append(models, m)
	}

	if len(models) > 0 {
		return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			// upsert clause is moved to model.Resource.BeforeCreate() (gorm's hook) to apply the same for associations (model.Resource.Children)
			if err := r.db.
				Session(&gorm.Session{CreateBatchSize: 1000}).
				Create(models).Error; err != nil {
				return err
			}

			for i, m := range models {
				r, err := m.ToDomain()
				if err != nil {
					return err
				}
				*resources[i] = *r
			}

			return nil
		})
	}

	return nil
}

// Update record by ID
func (r *ResourceRepository) Update(ctx context.Context, res *domain.Resource) error {
	if res.ID == "" {
		return resource.ErrEmptyIDParam
	}

	m := new(model.Resource)
	if err := m.FromDomain(res); err != nil {
		return err
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(m).Where(`"id" = ?`, res.ID).Updates(*m).Error; err != nil {
			return err
		}

		newRecord, err := m.ToDomain()
		if err != nil {
			return err
		}

		*res = *newRecord

		return nil
	})
}

func (r *ResourceRepository) Delete(ctx context.Context, id string) error {
	if id == "" {
		return resource.ErrEmptyIDParam
	}
	whereClause := `"id" = ?`
	if _, err := uuid.Parse(id); err != nil {
		whereClause = `"global_urn" = ?`
	}

	result := r.db.WithContext(ctx).Where(whereClause, id).Delete(&model.Resource{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return resource.ErrRecordNotFound
	}

	return nil
}

func (r *ResourceRepository) BatchDelete(ctx context.Context, ids []string) error {
	if ids == nil {
		return resource.ErrEmptyIDParam
	}

	result := r.db.WithContext(ctx).Delete(&model.Resource{}, ids)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return resource.ErrRecordNotFound
	}

	return nil
}
