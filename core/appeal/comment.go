package appeal

import (
	"context"
	"fmt"

	"github.com/goto/guardian/domain"
)

const CommentParentTypeAppeal = "appeal"

func (s *Service) CreateComment(ctx context.Context, c *domain.Comment) error {
	appealID := c.ParentID
	appeal, err := s.GetByID(ctx, appealID)
	if err != nil {
		return fmt.Errorf("failed to get appeal details: %w", err)
	}
	c.ParentType = CommentParentTypeAppeal

	if err := s.commentService.Create(ctx, c); err != nil {
		return err
	}

	go func() {
		ctx := context.WithoutCancel(ctx)
		if err := s.notifyParticipants(ctx, appeal, c); err != nil {
			s.logger.Error(ctx, "failed to notify participants", "error", err, "appeal_id", c.ParentID, "comment_id", c.ID)
		}
	}()

	return nil
}

func (s *Service) ListComments(ctx context.Context, filter domain.ListCommentsFilter) ([]*domain.Comment, error) {
	appealID := filter.ParentID
	_, err := s.GetByID(ctx, appealID)
	if err != nil {
		return nil, fmt.Errorf("failed to get appeal details: %w", err)
	}
	filter.ParentType = CommentParentTypeAppeal
	return s.commentService.List(ctx, filter)
}

func (s *Service) notifyParticipants(ctx context.Context, appeal *domain.Appeal, comment *domain.Comment) error {
	notifRecipients := map[string]bool{}

	// add appeal creator
	notifRecipients[appeal.CreatedBy] = true

	// add approvers from the current pending approval
	if pendingApproval := appeal.GetNextPendingApproval(); pendingApproval != nil {
		for _, approver := range pendingApproval.Approvers {
			notifRecipients[approver] = true
		}
	}

	// add anyone who has commented before
	comments, err := s.commentService.List(ctx, domain.ListCommentsFilter{
		ParentType: CommentParentTypeAppeal,
		ParentID:   appeal.ID,
	})
	if err != nil {
		return fmt.Errorf("failed to get comments of appeal %q: %w", comment.ParentID, err)
	}
	for _, c := range comments {
		notifRecipients[c.CreatedBy] = true
	}

	// remove current comment creator
	delete(notifRecipients, comment.CreatedBy)

	// send notifications
	var notifications []domain.Notification
	for recipient := range notifRecipients {
		notifications = append(notifications, domain.Notification{
			User: recipient,
			Message: domain.NotificationMessage{
				Type: domain.NotificationTypeNewComment,
				Variables: map[string]interface{}{
					"appeal_id":          appeal.ID,
					"appeal_created_by":  appeal.CreatedBy,
					"resource_name":      fmt.Sprintf("%s (%s: %s)", appeal.Resource.Name, appeal.Resource.ProviderType, appeal.Resource.URN),
					"comment_id":         comment.ID,
					"comment_created_by": comment.CreatedBy,
					"body":               comment.Body,
				},
			},
		})
	}
	if len(notifications) > 0 {
		if errs := s.notifier.Notify(ctx, notifications); errs != nil {
			for _, err := range errs {
				s.logger.Error(ctx, "failed to send notifications", "error", err.Error())
			}
		}
	}

	return nil
}
