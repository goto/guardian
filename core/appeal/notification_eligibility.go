package appeal

import (
	"context"

	"github.com/goto/guardian/domain"
)

// Only routine outcomes are suppressed. An outstanding human approval or an
// explicit comment must remain visible, even on a technical child appeal.
func (s *Service) filterTechnicalNotifications(ctx context.Context, notifications []domain.Notification, appeals ...*domain.Appeal) []domain.Notification {
	reasons := map[string]string{}
	for _, a := range appeals {
		if a != nil && a.ID != "" {
			if reason := a.NotificationSuppressionReason(); reason != "" {
				reasons[a.ID] = reason
			}
		}
	}
	result := make([]domain.Notification, 0, len(notifications))
	for _, n := range notifications {
		reason := reasons[n.Labels["appeal_id"]]
		switch n.Message.Type {
		case domain.NotificationTypeAppealApproved, domain.NotificationTypeOnBehalfAppealApproved, domain.NotificationTypeAppealRejected:
			if reason != "" {
				s.logger.Info(ctx, "skipping technical appeal outcome notification", "appeal_id", n.Labels["appeal_id"], "type", n.Message.Type, "reason", reason)
				continue
			}
		}
		result = append(result, n)
	}
	return result
}
