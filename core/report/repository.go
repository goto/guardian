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

func (r *Repository) GetPendingApprovalsList(ctx context.Context, filters *ReportFilter) (*[]Report, error) {
	m := new([]Report)
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
		db.ScanRows(rows, &m)
	}

	return m, nil
}

func applyAppealFilter(db *gorm.DB, filters *ReportFilter) (*gorm.DB, error) {
	db = db.Table("appeals as ap").
		Select("ap.id, aprs.email as approver, ap.created_by as requestor, apr.name as project, rs.provider_type as resource, ap.status as status, ap.created_by").
		Joins("join resources rs on ap.resource_id = rs.id").
		Joins("join approvals apr on ap.id = apr.appeal_id").
		Joins("join approvers aprs on aprs.approval_id = apr.id")

	if filters.ApprovalStatuses != nil {
		db = db.Where(`"appeals"."status" IN ?`, filters.AppealStatuses)
	}

	if filters.ApprovalStatuses != nil {
		db = db.Where(`"appeals"."status" IN ?`, filters.ApprovalStatuses)
	}

	return db, nil
}
