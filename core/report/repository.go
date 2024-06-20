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

func (r *Repository) GetPendingApprovalsList(ctx context.Context, filters *PendingApprovalsReportFilter) ([]*PendingApprovalModel, error) {
	records := []*PendingApprovalModel{}

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
	db = db.Table("approvers").
		Select("appeals.id as appeal_id, approvers.email as approver, appeals.created_at as appeal_created_at").
		Joins("join approvals on approvals.id = approvers.approval_id").
		Joins("join appeals on appeals.id = approvals.appeal_id").
		Where("approvers.deleted_at IS NULL").
		Where("approvals.deleted_at IS NULL").
		Where("appeals.deleted_at IS NULL")

	if filters.AppealStatuses != nil {
		db = db.Where(`"appeals"."status" IN ?`, filters.AppealStatuses)
	}

	if filters.ApprovalStatuses != nil {
		db = db.Where(`"approvals"."status" IN ?`, filters.ApprovalStatuses)
	}

	if filters.ApprovalStale != nil {
		db = db.Where(`"approvals"."is_stale" = ?`, *filters.ApprovalStale)
	}

	return db, nil
}
