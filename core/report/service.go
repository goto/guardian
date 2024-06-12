package report

import (
	"context"

	"gorm.io/gorm"

	"github.com/goto/guardian/utils"
)

type ServiceDeps struct {
	DB *gorm.DB
}

type Service struct {
	db *gorm.DB
}

func NewService(deps ServiceDeps) *Service {
	return &Service{
		deps.DB,
	}
}

func (s *Service) GetPendingApprovalsList(ctx context.Context, filters ReportFilter) ([]Report, error) {
	if err := utils.ValidateStruct(filters); err != nil {
		return nil, err
	}

	records := []Report{}
	db := s.db.WithContext(ctx)
	query := `
		select
			ap.id,
			aprs.email as approver,
			ap.created_by as requestor,
			apr.name as project,
			rs.provider_type as resource,
			ap.status as status,
			ap.created_by
		from appeals ap 
		join resources rs on ap.resource_id = rs.id 
		join approvals apr on ap.id = apr.appeal_id 
		join approvers aprs on aprs.approval_id = apr.id 
		where ap.status in ? and apr.status in ?
	`
	rows, err := db.Raw(query, filters.ApprovalStatuses, filters.AppealStatuses).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		db.ScanRows(rows, &records)
	}

	return records, nil
}
