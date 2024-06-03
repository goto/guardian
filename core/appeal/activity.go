package appeal

import (
	"context"

	"github.com/goto/guardian/domain"
)

func (s *Service) ListActivities(ctx context.Context, appealID string) ([]*domain.Event, error) {
	return s.eventService.List(ctx, &domain.ListEventsFilter{
		Types: []string{
			AuditKeyCancel,
			AuditKeyApprove,
			AuditKeyReject,
			AuditKeyAddApprover,
			AuditKeyDeleteApprover,
			AuditKeyUpdate,
		},
		ParentType: "appeal",
		ParentID:   appealID,
	})
}
