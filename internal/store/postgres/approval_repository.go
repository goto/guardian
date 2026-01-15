package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/lib/pq"
	"gorm.io/gorm"

	"github.com/goto/guardian/core/appeal"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/internal/store/postgres/model"
	slicesUtil "github.com/goto/guardian/pkg/slices"
	"github.com/goto/guardian/utils"
)

var (
	ApprovalStatusDefaultSort = []string{
		domain.ApprovalStatusPending,
		domain.ApprovalStatusApproved,
		domain.ApprovalStatusRejected,
		domain.ApprovalStatusBlocked,
		domain.ApprovalStatusSkipped,
	}

	approvalEntityGroupKeyMapping = map[string]string{
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
	if err := db.Preload("Appeal.Resource").
		Preload("Appeal.Approvals").
		Preload("Appeal.Approvals.Approvers").
		Find(&models).Error; err != nil {
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
	db = applyApprovalsJoins(db)

	// omit offset & size & order_by
	f := *filter
	f.Size = 0
	f.Offset = 0
	f.OrderBy = nil

	var err error
	db, err = applyApprovalsFilter(db, &f)
	if err != nil {
		return 0, err
	}
	var count int64
	if err = db.Model(&model.Approval{}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *ApprovalRepository) GenerateApprovalSummary(ctx context.Context, filter *domain.ListApprovalsFilter, groupBys []string) (*domain.SummaryResult, error) {
	var err error
	if err = utils.ValidateStruct(filter); err != nil {
		return nil, err
	}

	sr := new(domain.SummaryResult)

	dbGen := func() (*gorm.DB, error) {
		// omit offset & size & order_by
		f := *filter
		f.Offset = 0
		f.Size = 0
		f.OrderBy = nil

		db := r.db.WithContext(ctx)
		db = applyApprovalsSummaryJoins(db)
		return applyApprovalsFilter(db, &f)
	}

	// omit offset & size & order_by for group summaries
	if len(groupBys) > 0 {
		sr.SummaryGroups, err = generateGroupSummaries(ctx, dbGen, "approvals", groupBys, nil, approvalEntityGroupKeyMapping)
		if err != nil {
			return nil, err
		}
		sr = generateSummaryResultCount(sr)
		sr.Count = sr.GroupsCount
	}

	return sr, nil
}

func (r *ApprovalRepository) GenerateSummary(ctx context.Context, filter domain.ListApprovalsFilter) (*domain.SummaryResult, error) {
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
		db = applyApprovalsSummaryJoins(db)
		return applyApprovalsFilter(db, &f)
	}

	if len(filter.SummaryUniques) > 0 {
		sr.SummaryUniques, err = generateUniqueSummaries(ctx, dbGen, "approvals", filter.SummaryUniques, approvalEntityGroupKeyMapping)
		if err != nil {
			return nil, err
		}
	}

	if len(filter.SummaryGroupBys) > 0 {
		sr.SummaryGroups, err = generateGroupSummaries(ctx, dbGen, "approvals", filter.SummaryGroupBys, nil, approvalEntityGroupKeyMapping)
		if err != nil {
			return nil, err
		}
	}

	return generateSummaryResultCount(sr), nil
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

func applyApprovalsSummaryJoins(db *gorm.DB) *gorm.DB {
	return db.Joins(`LEFT JOIN "appeals" "Appeal" ON "approvals"."appeal_id" = "Appeal"."id"`).
		Joins(`LEFT JOIN "resources" "Appeal__Resource" ON "Appeal"."resource_id" = "Appeal__Resource"."id"`).
		Joins(`LEFT JOIN "approvers" ON "approvals"."id" = "approvers"."approval_id"`)
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
		db = db.Where(`"approvers"."email" = ?`, strings.ToLower(filter.CreatedBy))
	}
	if filter.Statuses != nil {
		db = db.Where(`"approvals"."status" IN ?`, filter.Statuses)
	}
	if filter.AccountID != "" {
		filter.AccountIDs = slicesUtil.GenericsStandardizeSlice(append(filter.AccountIDs, filter.AccountID))
	}
	if len(filter.AccountIDs) > 0 {
		db = db.Where(`LOWER("Appeal"."account_id") IN ?`, slicesUtil.ToLowerStringSlice(filter.AccountIDs))
	}
	if len(filter.Requestors) > 0 {
		db = db.Where(`LOWER("Appeal"."created_by") IN ?`, slicesUtil.ToLowerStringSlice(filter.Requestors))
	}
	if filter.AccountTypes != nil {
		db = db.Where(`"Appeal"."account_type" IN ?`, filter.AccountTypes)
	}
	if filter.ProviderTypes != nil {
		db = db.Where(`"Appeal__Resource"."provider_type" IN ?`, filter.ProviderTypes)
	}
	if filter.ResourceTypes != nil {
		db = db.Where(`"Appeal__Resource"."type" IN ?`, filter.ResourceTypes)
	}
	if len(filter.ResourceUrns) > 0 {
		db = db.Where(`"Appeal__Resource"."urn" IN ?`, filter.ResourceUrns)
	}

	if len(filter.AppealStatuses) == 0 {
		db = db.Where(`"Appeal"."status" != ?`, domain.AppealStatusCanceled)
	} else {
		db = db.Where(`"Appeal"."status" IN ?`, filter.AppealStatuses)
	}

	if len(filter.OrderBy) > 0 {
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

	rolePatterns, err := buildLikePatterns(filter.RoleStartsWith, filter.RoleEndsWith, filter.RoleContains, filter.Roles, "role")
	if err != nil {
		return nil, err
	}
	if len(rolePatterns) > 0 {
		db = db.Where(`"Appeal"."role" LIKE ANY (?)`, pq.Array(rolePatterns))
	}

	roleNotPatterns, err := buildLikePatterns(filter.RoleNotStartsWith, filter.RoleNotEndsWith, filter.RoleNotContains, nil, "role_not")
	if err != nil {
		return nil, err
	}
	if len(roleNotPatterns) > 0 {
		db = db.Where(`"Appeal"."role" NOT LIKE ANY (?)`, pq.Array(roleNotPatterns))
	}

	providerUrnPatterns, err := buildLikePatterns(filter.ProviderUrnStartsWith, filter.ProviderUrnEndsWith, filter.ProviderUrnContains, filter.ProviderURNs, "provider_urn")
	if err != nil {
		return nil, err
	}
	if len(providerUrnPatterns) > 0 {
		db = db.Where(`"Appeal__Resource"."provider_urn" LIKE ANY (?)`, pq.Array(providerUrnPatterns))
	}

	providerUrnNotPatterns, err := buildLikePatterns(filter.ProviderUrnNotStartsWith, filter.ProviderUrnNotEndsWith, filter.ProviderUrnNotContains, nil, "provider_urn_not")
	if err != nil {
		return nil, err
	}
	if len(providerUrnNotPatterns) > 0 {
		db = db.Where(`"Appeal__Resource"."provider_urn" NOT LIKE ANY (?)`, pq.Array(providerUrnNotPatterns))
	}

	if len(filter.AppealDurations) > 0 {
		db = db.Where(`"Appeal"."options" #>> '{duration}' IN ?`, filter.AppealDurations)
	}
	if len(filter.NotAppealDurations) > 0 {
		db = db.Where(`"Appeal"."options" #>> '{duration}' NOT IN ?`, filter.NotAppealDurations)
	}

	for _, appealDetailsPath := range filter.AppealDetailsPaths {
		appealDetailsPath = strings.TrimSpace(appealDetailsPath)
		if len(appealDetailsPath) == 0 {
			continue
		}
		appealDetailsPath = strings.ReplaceAll(appealDetailsPath, ".", ",")
		if len(filter.AppealDetails) > 0 {
			db = db.Where(fmt.Sprintf(`"Appeal"."details" #>> '{%s}' IN ?`, appealDetailsPath), filter.AppealDetails)
		}
		if len(filter.NotAppealDetails) > 0 {
			db = db.Where(fmt.Sprintf(`"Appeal"."details" #>> '{%s}' NOT IN ?`, appealDetailsPath), filter.NotAppealDetails)
		}
	}

	if len(filter.StepNames) > 0 {
		db = db.Where(`"approvals"."name" IN ?`, filter.StepNames)
	}
	if len(filter.Actors) > 0 {
		db = db.Where(`"approvals"."actor" IN ?`, filter.Actors)
	}

	if !filter.StartTime.IsZero() && !filter.EndTime.IsZero() {
		db = db.Where(`"Appeal"."created_at" BETWEEN ? AND ?`, filter.StartTime, filter.EndTime)
	} else if !filter.StartTime.IsZero() {
		db = db.Where(`"Appeal"."created_at" >= ?`, filter.StartTime)
	} else if !filter.EndTime.IsZero() {
		db = db.Where(`"Appeal"."created_at" <= ?`, filter.EndTime)
	}

	return db, nil
}
