package comment_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/goto/guardian/core/comment"
	"github.com/goto/guardian/core/comment/mocks"
	"github.com/goto/guardian/domain"
	guardianmocks "github.com/goto/guardian/mocks"
	"github.com/goto/guardian/pkg/log"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type ServiceTestSuite struct {
	suite.Suite
	mockCommentRepo *mocks.Repository
	mockAuditLogger *guardianmocks.AuditLogger
	service         *comment.Service
}

func (s *ServiceTestSuite) SetupTest() {
	s.mockCommentRepo = &mocks.Repository{}
	s.mockAuditLogger = new(guardianmocks.AuditLogger)

	s.service = comment.NewService(comment.ServiceDeps{
		Repository:  s.mockCommentRepo,
		AuditLogger: s.mockAuditLogger,
		Logger:      log.NewNoop(),
	})
}

func TestService(t *testing.T) {
	suite.Run(t, new(ServiceTestSuite))
}

func (s *ServiceTestSuite) TestCreate() {
	s.Run("should return list of comments on success", func() {
		parentType := "test-parent-type"
		parentID := uuid.New().String()

		s.mockCommentRepo.EXPECT().
			Create(mock.MatchedBy(func(ctx context.Context) bool { return true }), mock.MatchedBy(func(comment *domain.Comment) bool {
				return comment.ParentType == parentType &&
					comment.ParentID == parentID &&
					comment.CreatedBy != "" &&
					comment.Body != ""
			})).
			Return(nil)

		newComment := &domain.Comment{
			ParentType: parentType,
			ParentID:   parentID,
			CreatedBy:  "comment.creator@example.com",
			Body:       "test comment content",
		}

		s.mockAuditLogger.EXPECT().
			Log(mock.MatchedBy(func(ctx context.Context) bool { return true }), comment.AuditKeyCreate, newComment).
			Return(nil)

		actualErr := s.service.Create(context.Background(), newComment)
		s.NoError(actualErr)

		time.Sleep(2 * time.Second) // wait for async actions to complete
		s.mockCommentRepo.AssertExpectations(s.T())
		s.mockAuditLogger.AssertExpectations(s.T())
	})
}

func (s *ServiceTestSuite) TestList() {
	s.Run("should return list of comments on success", func() {
		parentID := uuid.New().String()

		expectedComments := []*domain.Comment{
			{ID: uuid.New().String(), ParentType: "test-parent-type", ParentID: parentID, CreatedBy: "user1@example.com", Body: "comment 1"},
			{ID: uuid.New().String(), ParentType: "test-parent-type", ParentID: parentID, CreatedBy: "user2@example.com", Body: "comment 2"},
		}
		s.mockCommentRepo.EXPECT().
			List(mock.MatchedBy(func(ctx context.Context) bool { return true }), mock.AnythingOfType("domain.ListCommentsFilter")).
			Return(expectedComments, nil).
			Run(func(_a0 context.Context, filter domain.ListCommentsFilter) {
				s.Equal(parentID, filter.ParentID)
				defaultSort := []string{"created_at"}
				s.Equal(defaultSort, filter.OrderBy)
			})

		actualComments, actualErr := s.service.List(context.Background(), domain.ListCommentsFilter{ParentID: parentID})
		s.NoError(actualErr)
		s.Equal(expectedComments, actualComments)
	})
}
