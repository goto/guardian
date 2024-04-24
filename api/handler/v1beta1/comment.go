package v1beta1

import (
	"context"
	"errors"

	guardianv1beta1 "github.com/goto/guardian/api/proto/gotocompany/guardian/v1beta1"
	"github.com/goto/guardian/core/appeal"
	"github.com/goto/guardian/core/comment"
	"github.com/goto/guardian/domain"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *GRPCServer) ListAppealComments(ctx context.Context, req *guardianv1beta1.ListAppealCommentsRequest) (*guardianv1beta1.ListAppealCommentsResponse, error) {
	comments, err := s.appealService.ListComments(ctx, domain.ListCommentsFilter{
		ParentID: req.GetAppealId(),
		OrderBy:  req.GetOrderBy(),
	})
	if err != nil {
		switch {
		case errors.Is(err, appeal.ErrAppealNotFound):
			return nil, status.Errorf(codes.NotFound, err.Error())
		default:
			return nil, s.internalError(ctx, "failed to list comments: %s", err)
		}
	}

	commentProtos := []*guardianv1beta1.Comment{}
	for _, c := range comments {
		commentProtos = append(commentProtos, s.adapter.ToCommentProto(c))
	}

	return &guardianv1beta1.ListAppealCommentsResponse{
		Comments: commentProtos,
	}, nil
}

func (s *GRPCServer) CreateAppealComment(ctx context.Context, req *guardianv1beta1.CreateAppealCommentRequest) (*guardianv1beta1.CreateAppealCommentResponse, error) {
	actor, err := s.getUser(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	c := &domain.Comment{
		ParentID:  req.GetAppealId(),
		Body:      req.GetBody(),
		CreatedBy: actor,
	}
	if err := s.appealService.CreateComment(ctx, c); err != nil {
		switch {
		case
			errors.Is(err, comment.ErrEmptyCommentParentType),
			errors.Is(err, comment.ErrEmptyCommentParentID),
			errors.Is(err, comment.ErrEmptyCommentCreator),
			errors.Is(err, comment.ErrEmptyCommentBody):
			return nil, s.invalidArgument(ctx, err.Error())
		case errors.Is(err, appeal.ErrAppealNotFound):
			return nil, status.Errorf(codes.NotFound, err.Error())
		default:
			return nil, s.internalError(ctx, "failed to create comment: %s", err)
		}
	}

	return &guardianv1beta1.CreateAppealCommentResponse{
		Comment: s.adapter.ToCommentProto(c),
	}, nil
}
