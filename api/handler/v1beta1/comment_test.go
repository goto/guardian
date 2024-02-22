package v1beta1_test

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	guardianv1beta1 "github.com/goto/guardian/api/proto/gotocompany/guardian/v1beta1"
	"github.com/goto/guardian/core/appeal"
	"github.com/goto/guardian/core/comment"
	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *GrpcHandlersSuite) TestListComments() {
	s.Run("should return list of comments on success", func() {
		s.setup()
		timeNow := time.Now()

		appealID := uuid.New().String()
		dummyComments := []*domain.Comment{
			{
				ID:        uuid.New().String(),
				AppealID:  appealID,
				CreatedBy: "user1@example.com",
				Body:      "comment 1",
				CreatedAt: timeNow,
				UpdatedAt: timeNow,
			},
			{
				ID:        uuid.New().String(),
				AppealID:  appealID,
				CreatedBy: "user2@example.com",
				Body:      "comment 2",
				CreatedAt: timeNow,
				UpdatedAt: timeNow,
			},
		}
		expectedResponse := &guardianv1beta1.ListAppealCommentsResponse{
			Comments: []*guardianv1beta1.Comment{
				{
					Id:        dummyComments[0].ID,
					AppealId:  appealID,
					CreatedBy: "user1@example.com",
					Body:      "comment 1",
					CreatedAt: timestamppb.New(timeNow),
					UpdatedAt: timestamppb.New(timeNow),
				},
				{
					Id:        dummyComments[1].ID,
					AppealId:  appealID,
					CreatedBy: "user2@example.com",
					Body:      "comment 2",
					CreatedAt: timestamppb.New(timeNow),
					UpdatedAt: timestamppb.New(timeNow),
				},
			},
		}
		expectedOrderBy := []string{"created_at:desc"}

		s.commentService.EXPECT().
			List(mock.MatchedBy(func(ctx context.Context) bool { return true }), mock.AnythingOfType("domain.ListCommentsFilter")).
			Return(dummyComments, nil).
			Run(func(_a0 context.Context, filter domain.ListCommentsFilter) {
				s.Equal(appealID, filter.AppealID)
				s.Equal(expectedOrderBy, filter.OrderBy)
			})
		defer s.commentService.AssertExpectations(s.T())

		req := &guardianv1beta1.ListAppealCommentsRequest{
			AppealId: appealID,
			OrderBy:  expectedOrderBy,
		}
		res, err := s.grpcServer.ListAppealComments(context.Background(), req)

		s.NoError(err)
		s.Equal(expectedResponse, res)
	})

	s.Run("should return error codes according to the service error", func() {
		testCases := []struct {
			name             string
			expecedError     error
			expectedGRPCCode codes.Code
		}{
			{
				name:             "should return not found error when appeal not found",
				expecedError:     appeal.ErrAppealNotFound,
				expectedGRPCCode: codes.NotFound,
			},
			{
				name:             "should return internal error when service fails",
				expecedError:     errors.New("unexpected error"),
				expectedGRPCCode: codes.Internal,
			},
		}

		for _, tc := range testCases {
			s.Run(tc.name, func() {
				s.setup()

				appealID := uuid.New().String()
				s.commentService.EXPECT().
					List(mock.MatchedBy(func(ctx context.Context) bool { return true }), mock.AnythingOfType("domain.ListCommentsFilter")).
					Return(nil, tc.expecedError)
				defer s.commentService.AssertExpectations(s.T())

				req := &guardianv1beta1.ListAppealCommentsRequest{
					AppealId: appealID,
				}
				res, err := s.grpcServer.ListAppealComments(context.Background(), req)

				s.Equal(tc.expectedGRPCCode, status.Code(err))
				s.Nil(res)
			})
		}
	})
}

func (s *GrpcHandlersSuite) TestCreateComment() {
	s.Run("should return comment on success", func() {
		s.setup()
		timeNow := time.Now()

		appealID := uuid.New().String()
		actor := "user@example.com"
		commentBody := "test comment"
		expectedNewComment := &domain.Comment{
			ID:        uuid.New().String(),
			AppealID:  appealID,
			CreatedBy: actor,
			Body:      commentBody,
			CreatedAt: timeNow,
			UpdatedAt: timeNow,
		}
		expectedResponse := &guardianv1beta1.CreateAppealCommentResponse{
			Comment: &guardianv1beta1.Comment{
				Id:        expectedNewComment.ID,
				AppealId:  appealID,
				CreatedBy: actor,
				Body:      commentBody,
				CreatedAt: timestamppb.New(timeNow),
				UpdatedAt: timestamppb.New(timeNow),
			},
		}

		s.commentService.EXPECT().
			Create(mock.MatchedBy(func(ctx context.Context) bool { return true }), mock.AnythingOfType("*domain.Comment")).
			Return(nil).
			Run(func(_a0 context.Context, c *domain.Comment) {
				s.Equal(appealID, c.AppealID)
				s.Equal(actor, c.CreatedBy)
				s.Equal(commentBody, c.Body)

				// updated values
				c.ID = expectedNewComment.ID
				c.CreatedAt = expectedNewComment.CreatedAt
				c.UpdatedAt = expectedNewComment.UpdatedAt
			})
		defer s.commentService.AssertExpectations(s.T())

		req := &guardianv1beta1.CreateAppealCommentRequest{
			AppealId: appealID,
			Body:     commentBody,
		}
		ctx := context.WithValue(context.Background(), authEmailTestContextKey{}, actor)
		res, err := s.grpcServer.CreateAppealComment(ctx, req)

		s.NoError(err)
		s.Equal(expectedResponse, res)
	})

	s.Run("should return unauthenticated error when user is not authenticated", func() {
		s.setup()
		req := &guardianv1beta1.CreateAppealCommentRequest{
			AppealId: uuid.New().String(),
			Body:     "test comment content",
		}
		ctx := context.Background() // no authenticated user in context
		res, err := s.grpcServer.CreateAppealComment(ctx, req)

		s.Equal(codes.Unauthenticated, status.Code(err))
		s.Nil(res)
	})

	s.Run("should return error codes according to the service error", func() {
		testCases := []struct {
			name             string
			expecedError     error
			expectedGRPCCode codes.Code
		}{
			{
				name:             "should return invalid argument error when comment creator is empty",
				expecedError:     comment.ErrEmptyCommentCreator,
				expectedGRPCCode: codes.InvalidArgument,
			},
			{
				name:             "should return invalid argument error when comment body is empty",
				expecedError:     comment.ErrEmptyCommentBody,
				expectedGRPCCode: codes.InvalidArgument,
			},
			{
				name:             "should return not found error when appeal not found",
				expecedError:     appeal.ErrAppealNotFound,
				expectedGRPCCode: codes.NotFound,
			},
			{
				name:             "should return internal error when service fails",
				expecedError:     errors.New("unexpected error"),
				expectedGRPCCode: codes.Internal,
			},
		}

		for _, tc := range testCases {
			s.Run(tc.name, func() {
				s.setup()

				s.commentService.EXPECT().
					Create(mock.MatchedBy(func(ctx context.Context) bool { return true }), mock.AnythingOfType("*domain.Comment")).
					Return(tc.expecedError)
				defer s.commentService.AssertExpectations(s.T())

				req := &guardianv1beta1.CreateAppealCommentRequest{
					AppealId: uuid.New().String(),
					Body:     "test comment content",
				}
				ctx := context.WithValue(context.Background(), authEmailTestContextKey{}, "user@example.com")
				res, err := s.grpcServer.CreateAppealComment(ctx, req)

				s.Equal(tc.expectedGRPCCode, status.Code(err))
				s.Nil(res)
			})
		}
	})
}
