package postgres

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/lib/pq"
	"gorm.io/gorm"

	"github.com/goto/guardian/core/appeal"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/internal/store/postgres/model"
	"github.com/goto/guardian/utils"
)

const (
	countColumnAlias = "count"
)

var (
	ApprovalStatusDefaultSort = []string{
		domain.ApprovalStatusPending,
		domain.ApprovalStatusApproved,
		domain.ApprovalStatusRejected,
		domain.ApprovalStatusBlocked,
		domain.ApprovalStatusSkipped,
	}

	entityGroupKeyMapping = map[string]string{
		"resource": "Appeal__Resource",
		"appeal":   "Appeal",
		"approver": "approvers",
		"approval": "approvals",
	}
)

type ApprovalRepository struct {
	db *gorm.DB
}

func NewApprovalRepository(db *gorm.DB) *ApprovalRepository {
	return &ApprovalRepository{db}
}

func (r *ApprovalRepository) ListApprovals(ctx context.Context, filter *domain.ListApprovalsFilter) ([]*domain.Approval, error) {
	if err := utils.ValidateStruct(filter); err != nil {
		return nil, err
	}

	records := []*domain.Approval{}

	db := r.db.WithContext(ctx)
	db = applyApprovalsJoins(db)
	var err error
	db, err = applyApprovalsFilter(db, filter)
	if err != nil {
		return nil, err
	}
	if filter.Size > 0 {
		db = db.Limit(filter.Size)
	}

	if filter.Offset > 0 {
		db = db.Offset(filter.Offset)
	}

	var models []*model.Approval
	if err := db.Find(&models).Error; err != nil {
		return nil, err
	}

	for _, m := range models {
		approval, err := m.ToDomain()
		if err != nil {
			return nil, err
		}

		records = append(records, approval)
	}

	return records, nil
}

func (r *ApprovalRepository) GetApprovalsTotalCount(ctx context.Context, filter *domain.ListApprovalsFilter) (int64, error) {
	db := r.db.WithContext(ctx)
	f := *filter
	f.Size = 0
	f.Offset = 0
	db = applyApprovalsJoins(db)
	var err error
	db, err = applyApprovalsFilter(db, &f)
	if err != nil {
		return 0, err
	}
	var count int64
	if err := db.Model(&model.Approval{}).Count(&count).Error; err != nil {
		return 0, err
	}

	return count, nil
}

func (r *ApprovalRepository) GenerateApprovalSummary(ctx context.Context, filter *domain.ListApprovalsFilter, groupBys []string) (*domain.SummaryResult, error) {
	if err := utils.ValidateStruct(filter); err != nil {
		return nil, err
	}

	db := r.db.WithContext(ctx)
	db = applyApprovalsSummariesJoins(db)
	var err error
	db, err = applyApprovalsFilter(db, filter)
	if err != nil {
		return nil, err
	}
	var selectCols []string
	var groupCols []string
	// TODO | https://github.com/goto/guardian/pull/218#discussion_r2336292684
	// Add validation for group bys. e,g. filter to group by 'created_at' since it not make sense.
	for _, groupKey := range groupBys {
		var column string
		for i, field := range strings.Split(groupKey, ".") {
			if i == 0 {
				tableName, ok := entityGroupKeyMapping[field]
				if !ok {
					return nil, fmt.Errorf("%w %q", domain.ErrInvalidGroupByField, field)
				}
				column = fmt.Sprintf("%q", tableName)
				continue
			}

			column += "." + fmt.Sprintf("%q", field)
		}

		selectCols = append(selectCols, fmt.Sprintf(`%s AS %q`, column, groupKey))
		groupCols = append(groupCols, fmt.Sprintf("%q", groupKey))
	}
	selectCols = append(selectCols, fmt.Sprintf("COUNT(1) AS %s", countColumnAlias))

	db = db.Table("approvals").Select(strings.Join(selectCols, ", "))
	if len(groupBys) > 0 {
		db = db.Group(strings.Join(groupCols, ", "))
	}

	// Execute query
	rows, err := db.Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := &domain.SummaryResult{
		SummaryGroups: []*domain.SummaryGroup{},
		Count:         0,
	}

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		// Prepare scan destination
		values := make([]interface{}, len(cols))
		valuePtrs := make([]interface{}, len(cols))
		for i := range cols {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}

		groupFields := make(map[string]any)
		var count int32
		for i, col := range cols {
			groupValues := values[:i]
			val := values[i]
			switch col {
			case countColumnAlias:
				intValue, err := strconv.Atoi(fmt.Sprint(val))
				if err != nil {
					return nil, fmt.Errorf("invalid count value (%T) for group values: %v", val, groupValues)
				}
				count = int32(intValue)
			default:
				groupFields[col] = val
			}
		}
		if len(groupBys) > 0 {
			result.SummaryGroups = append(result.SummaryGroups, &domain.SummaryGroup{
				GroupFields: groupFields,
				Count:       count,
			})
		}
		result.Count += count
	}

	return result, nil
}

func (r *ApprovalRepository) BulkInsert(ctx context.Context, approvals []*domain.Approval) error {
	models := []*model.Approval{}
	for _, a := range approvals {
		m := new(model.Approval)
		if err := m.FromDomain(a); err != nil {
			return err
		}

		models = append(models, m)
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(models).Error; err != nil {
			return err
		}

		for i, m := range models {
			newApproval, err := m.ToDomain()
			if err != nil {
				return err
			}

			*approvals[i] = *newApproval
		}

		return nil
	})
}

func (r *ApprovalRepository) AddApprover(ctx context.Context, approver *domain.Approver) error {
	m := new(model.Approver)
	if err := m.FromDomain(approver); err != nil {
		return fmt.Errorf("parsing approver: %w", err)
	}

	result := r.db.Create(m)
	if result.Error != nil {
		return fmt.Errorf("inserting new approver: %w", result.Error)
	}

	newApprover := m.ToDomain()
	*approver = *newApprover
	return nil
}

func (r *ApprovalRepository) DeleteApprover(ctx context.Context, approvalID, email string) error {
	result := r.db.
		WithContext(ctx).
		Where("approval_id = ?", approvalID).
		Where("email = ?", email).
		Delete(&model.Approver{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return appeal.ErrApproverNotFound
	}

	return nil
}

func applyApprovalsJoins(db *gorm.DB) *gorm.DB {
	return db.Joins("Appeal").
		Joins("Appeal.Resource").
		Joins(`JOIN "approvers" ON "approvals"."id" = "approvers"."approval_id"`)
}

func applyApprovalsSummariesJoins(db *gorm.DB) *gorm.DB {
	return db.Joins(`LEFT JOIN "appeals" "Appeal" ON "approvals"."appeal_id" = "Appeal"."id"
  AND "Appeal"."deleted_at" IS NULL`).
		Joins(`LEFT JOIN "resources" "Appeal__Resource" ON "Appeal"."resource_id" = "Appeal__Resource"."id"
  AND "Appeal__Resource"."deleted_at" IS NULL`).
		Joins(`JOIN "approvers" ON "approvals"."id" = "approvers"."approval_id"`)
}

func applyApprovalsFilter(db *gorm.DB, filter *domain.ListApprovalsFilter) (*gorm.DB, error) {
	if filter.Q != "" {
		// NOTE: avoid adding conditions before this grouped where clause.
		// Otherwise, it will be wrapped in parentheses and the query will be invalid.
		db = db.Where(db.
			Where(`"Appeal"."account_id" LIKE ?`, fmt.Sprintf("%%%s%%", filter.Q)).
			Or(`"Appeal"."role" LIKE ?`, fmt.Sprintf("%%%s%%", filter.Q)).
			Or(`"Appeal__Resource"."urn" LIKE ?`, fmt.Sprintf("%%%s%%", filter.Q)).
			Or(`"Appeal__Resource"."name" LIKE ?`, fmt.Sprintf("%%%s%%", filter.Q)),
		)
	}
	if filter.CreatedBy != "" {
		db = db.Where(`LOWER("approvers"."email") = ?`, strings.ToLower(filter.CreatedBy))
	}
	if filter.Statuses != nil {
		db = db.Where(`"approvals"."status" IN ?`, filter.Statuses)
	}
	if filter.AccountID != "" {
		db = db.Where(`LOWER("Appeal"."account_id") = ?`, strings.ToLower(filter.AccountID))
	}
	if filter.AccountTypes != nil {
		db = db.Where(`"Appeal"."account_type" IN ?`, filter.AccountTypes)
	}
	if filter.ProviderTypes != nil {
		db = db.Where(`"Appeal__Resource"."provider_type" IN ?`, filter.ProviderTypes)
	}
	if filter.ProviderURNs != nil {
		db = db.Where(`"Appeal__Resource"."provider_urn" IN ?`, filter.ProviderURNs)
	}
	if filter.ResourceTypes != nil {
		db = db.Where(`"Appeal__Resource"."type" IN ?`, filter.ResourceTypes)
	}

	if len(filter.AppealStatuses) == 0 {
		db = db.Where(`"Appeal"."status" != ?`, domain.AppealStatusCanceled)
	} else {
		db = db.Where(`"Appeal"."status" IN ?`, filter.AppealStatuses)
	}

	if filter.OrderBy != nil {
		var err error
		db, err = addOrderByClause(db, filter.OrderBy, addOrderByClauseOptions{
			statusColumnName: `"approvals"."status"`,
			statusesOrder:    AppealStatusDefaultSort,
		},
			[]string{"updated_at", "created_at"})

		if err != nil {
			return nil, err
		}
	}

	if !filter.Stale {
		db = db.Where(`"approvals"."is_stale" = ?`, filter.Stale)
	}

	if (filter.RoleStartsWith != "" || filter.RoleEndsWith != "") && filter.RoleContains != "" {
		return nil, fmt.Errorf("invalid filter: role_contains cannot be used together with role_starts_with or role_ends_with")
	}
	var patterns []string
	if filter.RoleStartsWith != "" {
		patterns = append(patterns, filter.RoleStartsWith+"%")
	}
	if filter.RoleEndsWith != "" {
		patterns = append(patterns, "%"+filter.RoleEndsWith)
	}
	if filter.RoleContains != "" {
		patterns = append(patterns, "%"+filter.RoleContains+"%")
	}
	if len(patterns) > 0 {
		db = db.Where(`"Appeal"."role" LIKE ANY (?)`, pq.Array(patterns))
	}

	if len(filter.StepNames) > 0 {
		db = db.Where(`"approvals"."name" IN ?`, filter.StepNames)
	}
	return db, nil
}
