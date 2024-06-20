package report

import (
	"context"

	"github.com/goto/guardian/utils"
)

//go:generate mockery --name=repository --exported --with-expecter
type repository interface {
	GetPendingApprovalsList(ctx context.Context, filters *PendingApprovalsReportFilter) ([]*PendingApprovalsReport, error)
}

type ServiceDeps struct {
	Repository repository
}

type Service struct {
	repo repository
}

func NewService(deps ServiceDeps) *Service {
	return &Service{
		deps.Repository,
	}
}

func (s *Service) GetPendingApprovalsList(ctx context.Context, filters *PendingApprovalsReportFilter) ([]*PendingApprovalsReport, error) {
	if err := utils.ValidateStruct(filters); err != nil {
		return nil, err
	}

	return s.repo.GetPendingApprovalsList(ctx, filters)
}
