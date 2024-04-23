package comment

import (
	"context"
	"errors"
	"fmt"

	"github.com/goto/guardian/core/appeal"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/plugins/notifiers"
)

const (
	AuditKeyCreate = "comment.create"
)

var (
	ErrEmptyCommentCreator = errors.New("comment creator (\"created_by\") can't be empty")
	ErrEmptyCommentBody    = errors.New("comment can't be empty")
)

//go:generate mockery --name=repository --exported --with-expecter
type repository interface {
	Create(context.Context, *domain.Comment) error
	List(context.Context, domain.ListCommentsFilter) ([]*domain.Comment, error)
}

//go:generate mockery --name=notifier --exported --with-expecter
type notifier interface {
	notifiers.Client
}

//go:generate mockery --name=auditLogger --exported --with-expecter
type auditLogger interface {
	Log(ctx context.Context, action string, data interface{}) error
}

type Service struct {
	repo          repository
	appealService *appeal.Service

	notifier    notifier
	logger      log.Logger
	auditLogger auditLogger
}

type ServiceDeps struct {
	Repository    repository
	AppealService *appeal.Service

	Notifier    notifier
	Logger      log.Logger
	AuditLogger auditLogger
}

func NewService(deps ServiceDeps) *Service {
	return &Service{
		repo:          deps.Repository,
		appealService: deps.AppealService,
		notifier:      deps.Notifier,
		logger:        deps.Logger,
		auditLogger:   deps.AuditLogger,
	}
}

func (s *Service) Create(ctx context.Context, c *domain.Comment) error {
	appeal, err := s.appealService.GetByID(ctx, c.AppealID)
	if err != nil {
		return fmt.Errorf("failed to get appeal details: %w", err)
	}

	if c.CreatedBy == "" {
		return ErrEmptyCommentCreator
	}
	if c.Body == "" {
		return ErrEmptyCommentBody
	}

	if err := s.repo.Create(ctx, c); err != nil {
		return err
	}

	go func() {
		ctx := context.WithoutCancel(ctx)
		if err := s.notifyParticipants(ctx, appeal, c); err != nil {
			s.logger.Error(ctx, "failed to notify participants", "error", err, "appeal_id", c.AppealID, "comment_id", c.ID)
		}

		if err := s.auditLogger.Log(ctx, AuditKeyCreate, c); err != nil {
			s.logger.Error(ctx, "failed to record audit log", "error", err, "appeal_id", c.AppealID, "comment_id", c.ID)
		}
	}()

	return nil
}

func (s *Service) List(ctx context.Context, filter domain.ListCommentsFilter) ([]*domain.Comment, error) {
	_, err := s.appealService.GetByID(ctx, filter.AppealID)
	if err != nil {
		return nil, fmt.Errorf("failed to get appeal details: %w", err)
	}

	if filter.OrderBy == nil {
		defaultCommentOrder := "created_at"
		filter.OrderBy = []string{defaultCommentOrder}
	}

	return s.repo.List(ctx, filter)
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
	comments, err := s.repo.List(ctx, domain.ListCommentsFilter{AppealID: comment.AppealID})
	if err != nil {
		return fmt.Errorf("failed to get comments of appeal %q: %w", comment.AppealID, err)
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
