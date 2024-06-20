package report

import (
	"context"

	"gorm.io/gorm"
)

type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db}
}

func (r *Repository) GetPendingApprovalsList(ctx context.Context, filters *PendingApprovalsReportFilter) ([]*PendingApprovalsReport, error) {
	records := []*PendingApprovalsReport{}

	db := r.db.WithContext(ctx)
	var err error
	db, err = applyAppealFilter(db, filters)
	if err != nil {
		return nil, err
	}

	rows, err := db.Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		db.ScanRows(rows, &records)
	}

	return records, nil
}

func applyAppealFilter(db *gorm.DB, filters *PendingApprovalsReportFilter) (*gorm.DB, error) {
	db = db.Table("appeals").
		Select("appeals.id, approvers.email as approver, appeals.created_by as requestor, approvals.name as project, resources.provider_type as resource, appeals.status as status, appeals.created_by").
		Joins("join resources on appeals.resource_id = resources.id").
		Joins("join approvals on appeals.id = approvals.appeal_id").
		Joins("join approvers on approvers.approval_id = approvals.id").
		Where("approvers.deleted_at IS NULL")

	if filters.AppealStatuses != nil {
		db = db.Where(`"appeals"."status" IN ?`, filters.AppealStatuses)
	}

	if filters.ApprovalStatuses != nil {
		db = db.Where(`"approvals"."status" IN ?`, filters.ApprovalStatuses)
	}

	return db, nil
}
