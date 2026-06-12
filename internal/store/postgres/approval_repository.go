package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/lib/pq"
	"gorm.io/gorm"

	"github.com/goto/guardian/core/appeal"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/internal/store/postgres/model"
	slicesUtil "github.com/goto/guardian/pkg/slices"
	"github.com/goto/guardian/utils"
)

// approvalRowWithPreviousGrant is a scan-only wrapper used by ListApprovals when
// WithPreviousGrant=true. The extra column is materialized by an aliased subquery in
// the SELECT and scanned into PreviousGrantExpirationDate. It is intentionally NOT a
// field on model.Approval — GORM would otherwise auto-include it in every Preload of
// approvals (in appeal_repository, grant_repository, and this file), generating SQL
// that references a non-existent column.
type approvalRowWithPreviousGrant struct {
	model.Approval
	PreviousGrantExpirationDate sql.NullTime `gorm:"column:previous_grant_expiration_date"`
}

// TableName overrides GORM's default snake-case-pluralization of the struct name
// (which would yield "approval_row_with_previous_grants"). Without this, every query
// using this wrapper fails with `relation "approval_row_with_previous_grants" does
// not exist`. The embedded model.Approval doesn't propagate its TableName to the outer
// type, so we have to set it explicitly here.
func (approvalRowWithPreviousGrant) TableName() string {
	return "approvals"
}

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

// lateralGrantJoinSQL materialises the latest grant for each approval row via a
// LEFT JOIN LATERAL. Using a lateral join instead of an inline correlated subquery means
// the grants lookup executes exactly once per outer row, regardless of how many times
// "lat_grant"."expiration_date" is referenced in WHERE or SELECT. The index
// idx_grants_account_resource_role_created covers the equality predicates and the
// ORDER BY, so each lookup is O(log n) and returns the first entry without a sort step.
//
// No status filter is applied: we want the most recently created grant regardless of
// whether it is still active or has already been revoked/expired. The expiry job sets
// status = 'inactive' on expired grants, so filtering status = 'active' would hide
// exactly the grants we need to detect for previousGrantStates=expired.
//
// is_permanent grants store expiration_date = 0001-01-01 (Go zero time). The CASE
// expression converts that to NULL so permanent grants are classified as "none"
// rather than falsely appearing as expired.
//
// The '1000-01-01' sentinel is used (instead of '0001-01-01') because the literal
// is parsed in the session timezone while stored timestamptz values are in UTC,
// and historical TZ offsets near year 0001 can cause Go's zero time to compare
// as greater than the literal. Year 1000 is safely past any TZ-ambiguity range.
const lateralGrantJoinSQL = `LEFT JOIN LATERAL (
	SELECT CASE
		WHEN "g"."revoked_at" > TIMESTAMPTZ '1000-01-01 00:00:00+00' THEN "g"."revoked_at"
		WHEN "g"."is_permanent" OR "g"."expiration_date" <= TIMESTAMPTZ '1000-01-01 00:00:00+00' THEN NULL
		ELSE "g"."expiration_date"
		END AS "expiration_date"
	FROM "grants" "g"
	WHERE "g"."account_id" = "Appeal"."account_id"
	  AND "g"."resource_id" = "Appeal"."resource_id"
	  AND "g"."role" = "Appeal"."role"
	  AND "g"."group_id" IS NOT DISTINCT FROM "Appeal"."group_id"
	  AND "g"."group_type" IS NOT DISTINCT FROM "Appeal"."group_type"
	ORDER BY "g"."created_at" DESC LIMIT 1
) "lat_grant" ON TRUE`

// needsLateralGrantJoin reports whether the filter requires the lat_grant lateral join.
func needsLateralGrantJoin(filter *domain.ListApprovalsFilter) bool {
	return filter.WithPreviousGrant ||
		!filter.StartExpirationDate.IsZero() ||
		!filter.EndExpirationDate.IsZero() ||
		len(filter.PreviousGrantStates) > 0
}

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

	orderByList := []string{
		"updated_at",
		"created_at",
	}

	var columnExpressions map[string]string
	var columnSuffixes map[string]string
	if filter.WithPreviousGrant {
		// Hydrate the derived previous_grant_expiration_date column on each returned row.
		// The lateral join was already added by applyApprovalsFilter, so we reference
		// "lat_grant"."expiration_date" directly instead of repeating the subquery.
		// When ExpiringWithinDays is set (without an explicit previousGrantStates filter),
		// we NULL out the expiration_date for grants outside the symmetric window instead
		// of filtering those rows out entirely, so all approvals are still returned.
		if filter.ExpiringWithinDays > 0 && len(filter.PreviousGrantStates) == 0 {
			db = db.Select(
				`"approvals".*, CASE WHEN "lat_grant"."expiration_date" BETWEEN NOW() - (? * INTERVAL '1 day') AND NOW() + (? * INTERVAL '1 day') THEN "lat_grant"."expiration_date" ELSE NULL END AS previous_grant_expiration_date`,
				filter.ExpiringWithinDays, filter.ExpiringWithinDays,
			)
		} else {
			db = db.Select(`"approvals".*, "lat_grant"."expiration_date" AS previous_grant_expiration_date`)
		}

		orderByList = append(orderByList, "previous_grant_expiration_date")
		var prevGrantExpr string
		if filter.ExpiringWithinDays > 0 && len(filter.PreviousGrantStates) == 0 {
			// Mirror the SELECT expression so ORDER BY sorts on the same nulled-out value.
			// ExpiringWithinDays is an int so direct embedding is safe.
			prevGrantExpr = fmt.Sprintf(
				`CASE WHEN "lat_grant"."expiration_date" BETWEEN NOW() - (%d * INTERVAL '1 day') AND NOW() + (%d * INTERVAL '1 day') THEN "lat_grant"."expiration_date" ELSE NULL END`,
				filter.ExpiringWithinDays, filter.ExpiringWithinDays,
			)
		} else {
			prevGrantExpr = `"lat_grant"."expiration_date"`
		}
		columnExpressions = map[string]string{
			"previous_grant_expiration_date": prevGrantExpr,
		}
		// Force NULLS LAST on both :asc and :desc so approvals with no previous grant
		// always sink to the bottom of the page, regardless of direction. Without this,
		// Postgres's default (NULLS FIRST on DESC) would put a wall of nulls on top.
		columnSuffixes = map[string]string{
			"previous_grant_expiration_date": "NULLS LAST",
		}
	}

	// Apply combined ORDER BY: exact-match priority (when Q is set) + user-specified order_by.
	// This is intentionally outside applyApprovalsFilter so it does not affect summary/count queries.
	if filter.Q != "" || len(filter.OrderBy) > 0 {
		var prependSQL string
		var prependVars []interface{}
		if filter.Q != "" {
			prependSQL = `CASE WHEN "Appeal"."account_id" = ? THEN 0 WHEN "Appeal"."role" = ? THEN 0 WHEN "Appeal__Resource"."urn" = ? THEN 0 WHEN "Appeal__Resource"."name" = ? THEN 0 ELSE 1 END`
			prependVars = []interface{}{filter.Q, filter.Q, filter.Q, filter.Q}
		}
		db, err = addOrderByClause(db, filter.OrderBy, addOrderByClauseOptions{
			statusColumnName:  `"approvals"."status"`,
			statusesOrder:     AppealStatusDefaultSort,
			prependSQL:        prependSQL,
			prependVars:       prependVars,
			columnExpressions: columnExpressions,
			columnSuffixes:    columnSuffixes,
		}, orderByList)
		if err != nil {
			return nil, err
		}
	}

	if filter.Size > 0 {
		db = db.Limit(filter.Size)
	}

	if filter.Offset > 0 {
		db = db.Offset(filter.Offset)
	}

	db = db.Preload("Appeal.Resource").
		Preload("Appeal.Approvals").
		Preload("Appeal.Approvals.Approvers")

	if filter.WithPreviousGrant {
		var rows []*approvalRowWithPreviousGrant
		if err := db.Find(&rows).Error; err != nil {
			return nil, err
		}
		for _, row := range rows {
			approval, err := row.Approval.ToDomain()
			if err != nil {
				return nil, err
			}
			if row.PreviousGrantExpirationDate.Valid {
				t := row.PreviousGrantExpirationDate.Time
				approval.PreviousGrantExpirationDate = &t
			}
			records = append(records, approval)
		}
		return records, nil
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

	dbGen := func(gCtx context.Context) (*gorm.DB, error) {
		// omit offset & size & order_by
		f := *filter
		f.Offset = 0
		f.Size = 0
		f.OrderBy = nil

		db := r.db.WithContext(gCtx)
		db = applyApprovalsSummaryJoins(db, filter.CreatedBy)
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

	dbGen := func(gCtx context.Context) (*gorm.DB, error) {
		// omit offset & size & order_by
		f := filter
		f.Offset = 0
		f.Size = 0
		f.OrderBy = nil

		db := r.db.WithContext(gCtx)
		db = applyApprovalsSummaryJoins(db, filter.CreatedBy)
		return applyApprovalsFilter(db, &f)
	}

	dbGenWithLabels := func(gCtx context.Context, labels map[string][]string) (*gorm.DB, error) {
		// Override f.Labels so applyApprovalsFilter only applies the given label filter,
		// leaving all other (non-label) filter conditions intact.
		// This is used by SummaryLabelsV2 (faceted search): for each label key K,
		// we query with all label filters EXCEPT K, so that the results show which
		// values for K are still available given the user's other active selections.
		f := filter
		f.Offset = 0
		f.Size = 0
		f.OrderBy = nil
		f.Labels = labels

		db := r.db.WithContext(gCtx)
		db = applyApprovalsSummaryJoins(db, filter.CreatedBy)
		return applyApprovalsFilter(db, &f)
	}

	if filter.SummaryLabels {
		sr.SummaryLabels, err = generateLabelSummaries(ctx, dbGen, "approvals", `"Appeal"."labels"`)
		if err != nil {
			return nil, err
		}
	}

	if filter.SummaryLabelsV2 {
		sr.SummaryLabelsV2, err = generateLabelSummariesV2(ctx, dbGenWithLabels, "approvals", `"Appeal"."labels"`, filter.Labels)
		if err != nil {
			return nil, err
		}
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

func (r *ApprovalRepository) UpdateApproval(ctx context.Context, approval *domain.Approval) error {
	m := new(model.Approval)
	if err := m.FromDomain(approval); err != nil {
		return fmt.Errorf("parsing approval: %w", err)
	}

	// Use Omit("Approvers") to prevent GORM from re-inserting the approvers association,
	// which would cause duplicate approver rows. We only want to update scalar fields.
	if err := r.db.WithContext(ctx).Omit("Approvers").Save(m).Error; err != nil {
		return fmt.Errorf("updating approval: %w", err)
	}

	newApproval, err := m.ToDomain()
	if err != nil {
		return fmt.Errorf("converting approval back to domain: %w", err)
	}
	*approval = *newApproval
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

// applyApprovalsSummaryJoins applies the joins for summary/count queries.
// When createdBy is set, approvers is INNER JOINed because the WHERE clause on
// approvers.email already excludes unmatched rows; making it explicit lets the
// planner choose a more efficient join order.
func applyApprovalsSummaryJoins(db *gorm.DB, createdBy string) *gorm.DB {
	db = db.Joins(`LEFT JOIN "appeals" "Appeal" ON "approvals"."appeal_id" = "Appeal"."id"`).
		Joins(`LEFT JOIN "resources" "Appeal__Resource" ON "Appeal"."resource_id" = "Appeal__Resource"."id"`)
	if createdBy != "" {
		db = db.Joins(`JOIN "approvers" ON "approvals"."id" = "approvers"."approval_id"`)
	} else {
		db = db.Joins(`LEFT JOIN "approvers" ON "approvals"."id" = "approvers"."approval_id"`)
	}
	return db
}

func applyApprovalsFilter(db *gorm.DB, filter *domain.ListApprovalsFilter) (*gorm.DB, error) {
	var err error

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
	if len(filter.StepNames) > 0 {
		db = db.Where(`"approvals"."name" IN ?`, filter.StepNames)
	}
	if len(filter.Actors) > 0 {
		db = db.Where(`"approvals"."actor" IN ?`, filter.Actors)
	}
	if !filter.Stale {
		db = db.Where(`"approvals"."is_stale" = ?`, filter.Stale)
	}
	if len(filter.GroupIDs) > 0 {
		db = db.Where(`"Appeal"."group_id" IN ?`, filter.GroupIDs)
	}
	if len(filter.AppealDurations) > 0 {
		db = db.Where(`COALESCE(NULLIF("Appeal"."options" #>> '{duration}', ''), 'null') IN ?`, filter.AppealDurations)
	}
	if len(filter.NotAppealDurations) > 0 {
		db = db.Where(`COALESCE(NULLIF("Appeal"."options" #>> '{duration}', ''), 'null') NOT IN ?`, filter.NotAppealDurations)
	}

	db, err = applyLikeAndInFilter(db, `"Appeal"."role"`,
		filter.RoleStartsWith, filter.RoleEndsWith, filter.RoleContains,
		filter.RoleNotStartsWith, filter.RoleNotEndsWith, filter.RoleNotContains,
		filter.Roles, nil, "role",
	)
	if err != nil {
		return nil, err
	}
	db, err = applyLikeAndInFilter(db, `"Appeal__Resource"."provider_urn"`,
		filter.ProviderUrnStartsWith, filter.ProviderUrnEndsWith, filter.ProviderUrnContains,
		filter.ProviderUrnNotStartsWith, filter.ProviderUrnNotEndsWith, filter.ProviderUrnNotContains,
		filter.ProviderURNs, nil, "provider_urn",
	)
	if err != nil {
		return nil, err
	}
	db, err = applyLikeAndInFilter(db, `"Appeal"."group_type"`,
		filter.GroupTypeStartsWith, filter.GroupTypeEndsWith, filter.GroupTypeContains,
		filter.GroupTypeNotStartsWith, filter.GroupTypeNotEndsWith, filter.GroupTypeNotContains,
		filter.GroupTypes, nil, "group_type",
	)
	if err != nil {
		return nil, err
	}
	db, err = applyJSONBPathsLikeAndInFilter(db, `"Appeal"."details"`, filter.AppealDetailsPaths,
		filter.AppealDetailsStartsWith, filter.AppealDetailsEndsWith, filter.AppealDetailsContains,
		filter.AppealDetailsNotStartsWith, filter.AppealDetailsNotEndsWith, filter.AppealDetailsNotContains,
		filter.AppealDetails, filter.NotAppealDetails, "appeal_details",
	)
	if err != nil {
		return nil, err
	}

	if len(filter.AppealDetailsForSelfCriteria) != 0 && len(filter.NotAppealDetailsForSelfCriteria) != 0 {
		return nil, fmt.Errorf("cannot use both appeal_details_for_self_criteria and not_appeal_details_for_self_criteria filters")
	}
	if len(filter.AppealDetailsForSelfCriteria) != 0 {
		var exprs []string
		for _, p := range filter.AppealDetailsForSelfCriteria {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			p = strings.ReplaceAll(p, ".", ",")
			exprs = append(exprs, fmt.Sprintf(`"Appeal"."details" #>> '{%s}'`, p))
		}
		if len(exprs) > 0 {
			db = db.Where(fmt.Sprintf(`"Appeal"."created_by" = ANY (ARRAY[%s])`, strings.Join(exprs, ",")))
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
			exprs = append(exprs, fmt.Sprintf(`COALESCE("Appeal"."details" #>> '{%s}', '')`, p))
		}
		if len(exprs) > 0 {
			db = db.Where(fmt.Sprintf(`NOT ("Appeal"."created_by" = ANY (ARRAY[%s]))`, strings.Join(exprs, ",")))
		}
	}

	if !filter.StartTime.IsZero() && !filter.EndTime.IsZero() {
		db = db.Where(`"Appeal"."created_at" BETWEEN ? AND ?`, filter.StartTime, filter.EndTime)
	} else if !filter.StartTime.IsZero() {
		db = db.Where(`"Appeal"."created_at" >= ?`, filter.StartTime)
	} else if !filter.EndTime.IsZero() {
		db = db.Where(`"Appeal"."created_at" <= ?`, filter.EndTime)
	}

	// Add the lateral grant join once when any grant-related filter or SELECT is needed.
	// This replaces the previous approach of embedding the same correlated subquery in each
	// WHERE condition, which caused it to be evaluated once per condition per row.
	if needsLateralGrantJoin(filter) {
		db = db.Joins(lateralGrantJoinSQL)
	}

	// Restrict by previous-grant expiration date.
	if !filter.StartExpirationDate.IsZero() || !filter.EndExpirationDate.IsZero() {
		var sub string
		args := []interface{}{}
		if !filter.StartExpirationDate.IsZero() && !filter.EndExpirationDate.IsZero() {
			sub = `"lat_grant"."expiration_date" BETWEEN ? AND ?`
			args = append(args, filter.StartExpirationDate, filter.EndExpirationDate)
		} else if !filter.StartExpirationDate.IsZero() {
			sub = `"lat_grant"."expiration_date" >= ?`
			args = append(args, filter.StartExpirationDate)
		} else {
			sub = `"lat_grant"."expiration_date" <= ?`
			args = append(args, filter.EndExpirationDate)
		}
		db = db.Where(sub, args...)
	}

	// Filter by previous-grant states. NULL from the lateral means either no previous grant
	// exists at all or the latest grant is permanent (expiration_date IS NULL) — both fall
	// under "none". For "expired" and "expiring", NULL is excluded automatically because any
	// comparison with NULL is NULL (falsy) in WHERE.
	// Multiple states are combined with OR so callers can request e.g. both "expired" and "expiring".
	if len(filter.PreviousGrantStates) > 0 {
		var orClauses []string
		var stateArgs []interface{}
		for _, state := range filter.PreviousGrantStates {
			switch state {
			case domain.PreviousGrantStateExpired:
				orClauses = append(orClauses, `"lat_grant"."expiration_date" < NOW()`)
			case domain.PreviousGrantStateExpiring:
				days := filter.ExpiringWithinDays
				if days == 0 {
					days = domain.DefaultExpiringWithinDays
				}
				orClauses = append(orClauses, `"lat_grant"."expiration_date" BETWEEN NOW() AND NOW() + (? * INTERVAL '1 day')`)
				stateArgs = append(stateArgs, days)
			case domain.PreviousGrantStateNone:
				orClauses = append(orClauses, `"lat_grant"."expiration_date" IS NULL`)
			}
		}
		if len(orClauses) > 0 {
			db = db.Where("("+strings.Join(orClauses, " OR ")+")", stateArgs...)
		}
	}

	// Label filtering
	if len(filter.Labels) > 0 {
		db = applyLabelFilter(db, `"Appeal"."labels"`, filter.Labels)
	}

	if len(filter.LabelKeys) > 0 {
		db = applyLabelKeyFilter(db, `"Appeal"."labels"`, filter.LabelKeys)
	}

	return db, nil
}
