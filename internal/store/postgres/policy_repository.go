package postgres

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"github.com/goto/guardian/core/policy"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/internal/store/postgres/model"
	"github.com/goto/guardian/utils"
)

// PolicyRepository talks to the store to read or insert data
type PolicyRepository struct {
	db *gorm.DB
}

// NewPolicyRepository returns repository struct
func NewPolicyRepository(db *gorm.DB) *PolicyRepository {
	return &PolicyRepository{db}
}

// Create new record to database
func (r *PolicyRepository) Create(ctx context.Context, p *domain.Policy) error {
	m := new(model.Policy)
	if err := m.FromDomain(p); err != nil {
		return fmt.Errorf("serializing policy: %w", err)
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if result := tx.Create(m); result.Error != nil {
			return result.Error
		}

		newPolicy, err := m.ToDomain()
		if err != nil {
			return fmt.Errorf("deserializing policy: %w", err)
		}

		*p = *newPolicy

		return nil
	})
}

// Find records based on filters
func (r *PolicyRepository) Find(ctx context.Context, filter domain.ListPoliciesFilter) ([]*domain.Policy, error) {
	if err := utils.ValidateStruct(filter); err != nil {
		return nil, err
	}

	records := []*domain.Policy{}

	db := r.db.WithContext(ctx)
	var err error
	db, err = applyPoliciesFilter(db, filter)
	if err != nil {
		return nil, err
	}

	if filter.Size > 0 {
		db = db.Limit(filter.Size)
	}
	if filter.Offset > 0 {
		db = db.Offset(filter.Offset)
	}

	var models []*model.Policy
	if err = db.Find(&models).Error; err != nil {
		return nil, err
	}
	for _, m := range models {
		p, err := m.ToDomain()
		if err != nil {
			return nil, err
		}

		records = append(records, p)
	}

	return records, nil
}

// GetOne returns a policy record based on the id and version params.
// If version is 0, the latest version will be returned
func (r *PolicyRepository) GetOne(ctx context.Context, id string, version uint) (*domain.Policy, error) {
	m := &model.Policy{}
	condition := "id = ?"
	args := []interface{}{id}
	if version != 0 {
		condition = "id = ? AND version = ?"
		args = append(args, version)
	}

	conds := append([]interface{}{condition}, args...)
	if err := r.db.WithContext(ctx).Order("version desc").First(m, conds...).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, policy.ErrPolicyNotFound
		}
		return nil, err
	}

	p, err := m.ToDomain()
	if err != nil {
		return nil, err
	}

	return p, nil
}

func applyPoliciesFilter(db *gorm.DB, filter domain.ListPoliciesFilter) (*gorm.DB, error) {
	var err error

	if len(filter.IDs) > 0 {
		db = applyPolicyIDsFilter(db, `"policies"`, filter.IDs)
	}

	if len(filter.OrderBy) > 0 {
		db, err = addOrderByClause(db, filter.OrderBy, addOrderByClauseOptions{}, []string{"id", "version", "updated_at", "created_at"})
		if err != nil {
			return nil, err
		}
	} else {
		// default order
		db = db.Order(`"policies"."id" ASC`).Order(`"policies"."version" DESC`)
	}

	return db, nil
}

func applyPolicyIDsFilter(db *gorm.DB, table string, ids []string) *gorm.DB {
	type policyIntent struct {
		All      bool
		Latest   bool
		Versions map[int]struct{}
	}

	intents := make(map[string]*policyIntent)

	for _, raw := range ids {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}

		parts := strings.Split(s, ":")
		if len(parts) > 2 {
			continue
		}

		id := strings.TrimSpace(parts[0])
		if id == "" {
			continue
		}

		intent, ok := intents[id]
		if !ok {
			intent = &policyIntent{
				Versions: make(map[int]struct{}),
			}
			intents[id] = intent
		}

		// "<id>" → all versions
		if len(parts) == 1 {
			intent.All = true
			continue
		}

		vStr := strings.TrimSpace(parts[1])
		if vStr == "" {
			continue
		}

		v, err := strconv.Atoi(vStr)
		if err != nil || v < 0 {
			continue
		}

		// "<id>:0" → latest
		if v == 0 {
			intent.Latest = true
			continue
		}

		// "<id>:n" → exact version
		intent.Versions[v] = struct{}{}
	}

	if len(intents) == 0 {
		return db
	}

	var conds []string
	var args []interface{}

	for id, intent := range intents {
		// ALL wins
		if intent.All {
			conds = append(conds, fmt.Sprintf(`%s."id" = ?`, table))
			args = append(args, id)
			continue
		}

		var subConds []string
		var subArgs []interface{}

		// latest
		if intent.Latest {
			subConds = append(subConds, fmt.Sprintf(`
				(%s."id" = ? AND %s."version" = (
					SELECT MAX(p2."version")
					FROM %s p2
					WHERE p2."id" = ?
				))
			`, table, table, table))
			subArgs = append(subArgs, id, id)
		}

		// exact versions
		if len(intent.Versions) > 0 {
			versions := make([]int, 0, len(intent.Versions))
			for v := range intent.Versions {
				versions = append(versions, v)
			}

			subConds = append(subConds,
				fmt.Sprintf(`(%s."id" = ? AND %s."version" IN ?)`, table, table),
			)
			subArgs = append(subArgs, id, versions)
		}

		if len(subConds) > 0 {
			conds = append(conds, "("+strings.Join(subConds, " OR ")+")")
			args = append(args, subArgs...)
		}
	}

	return db.Where(strings.Join(conds, " OR "), args...)
}
