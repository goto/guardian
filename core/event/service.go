package event

import (
	"context"
	"fmt"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/salt/audit"
)

//go:generate mockery --name=repository --exported --with-expecter
type repository interface {
	List(context.Context, *domain.ListAuditLogFilter) ([]*audit.Log, error)
}

type Service struct {
	repo repository
	log  log.Logger
}

func NewService(repo repository, log log.Logger) *Service {
	return &Service{repo: repo, log: log}
}

func (s *Service) List(ctx context.Context, filter *domain.ListEventsFilter) ([]*domain.Event, error) {
	var auditLogFilter *domain.ListAuditLogFilter
	if filter != nil {
		auditLogFilter = &domain.ListAuditLogFilter{
			Actions: filter.Types,
		}
		if filter.ParentType == "appeal" {
			auditLogFilter.AppealID = filter.ParentID
		}
	}

	logs, err := s.repo.List(ctx, auditLogFilter)
	if err != nil {
		return nil, err
	}

	events := make([]*domain.Event, 0, len(logs))
	for _, l := range logs {
		e := new(domain.Event)
		if err := e.FromAuditLog(l); err != nil {
			return nil, fmt.Errorf("failed to parse event: %w", err)
		}
		events = append(events, e)
	}

	return events, nil
}
