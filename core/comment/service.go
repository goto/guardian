package comment

import (
	"context"
	"errors"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/audit"
	"github.com/goto/guardian/pkg/log"
)

const (
	AuditKeyCreate = "comment.create"

	DefaultCommentsOrderBy = "created_at"
)

var (
	ErrEmptyCommentParentType = errors.New("parent type can't be empty")
	ErrEmptyCommentParentID   = errors.New("parent ID can't be empty")
	ErrEmptyCommentCreator    = errors.New("comment creator (\"created_by\") can't be empty")
	ErrEmptyCommentBody       = errors.New("comment can't be empty")
)

//go:generate mockery --name=repository --exported --with-expecter
type repository interface {
	Create(context.Context, *domain.Comment) error
	List(context.Context, domain.ListCommentsFilter) ([]*domain.Comment, error)
}

type Service struct {
	repo repository

	logger      log.Logger
	auditLogger audit.AuditLogger
}

type ServiceDeps struct {
	Repository repository

	Logger      log.Logger
	AuditLogger audit.AuditLogger
}

func NewService(deps ServiceDeps) *Service {
	return &Service{
		repo:        deps.Repository,
		logger:      deps.Logger,
		auditLogger: deps.AuditLogger,
	}
}

func (s *Service) Create(ctx context.Context, c *domain.Comment) error {
	switch {
	case c.ParentType == "":
		return ErrEmptyCommentParentType
	case c.ParentID == "":
		return ErrEmptyCommentParentID
	case c.CreatedBy == "":
		return ErrEmptyCommentCreator
	case c.Body == "":
		return ErrEmptyCommentBody
	}

	if err := s.repo.Create(ctx, c); err != nil {
		return err
	}

	go func() {
		ctx := context.WithoutCancel(ctx)
		if err := s.auditLogger.Log(ctx, AuditKeyCreate, c); err != nil {
			s.logger.Error(ctx, "failed to record audit log", "error", err, "appeal_id", c.ParentID, "comment_id", c.ID)
		}
	}()

	return nil
}

func (s *Service) List(ctx context.Context, filter domain.ListCommentsFilter) ([]*domain.Comment, error) {
	if filter.OrderBy == nil {
		filter.OrderBy = []string{DefaultCommentsOrderBy}
	}

	return s.repo.List(ctx, filter)
}
