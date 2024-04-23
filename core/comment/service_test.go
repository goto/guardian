package comment_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/goto/guardian/core/appeal"
	appealmock "github.com/goto/guardian/core/appeal/mocks"
	"github.com/goto/guardian/core/comment"
	"github.com/goto/guardian/core/comment/mocks"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type ServiceTestSuite struct {
	suite.Suite
	mockAppealRepo  *appealmock.Repository
	mockCommentRepo *mocks.Repository
	mockNotifier    *mocks.Notifier
	mockAuditLogger *mocks.AuditLogger
	service         *comment.Service
}

func (s *ServiceTestSuite) SetupTest() {
	s.mockAppealRepo = new(appealmock.Repository)
	s.mockCommentRepo = &mocks.Repository{}
	s.mockNotifier = &mocks.Notifier{}
	s.mockAuditLogger = &mocks.AuditLogger{}

	appealService := appeal.NewService(appeal.ServiceDeps{
		Repository:      s.mockAppealRepo,
		ResourceService: new(appealmock.ResourceService),
		ApprovalService: new(appealmock.ApprovalService),
		ProviderService: new(appealmock.ProviderService),
		PolicyService:   new(appealmock.PolicyService),
		GrantService:    new(appealmock.GrantService),
		IAMManager:      new(appealmock.IamManager),
		Notifier:        s.mockNotifier,
		Validator:       validator.New(),
		Logger:          log.NewNoop(),
		AuditLogger:     s.mockAuditLogger,
	})

	s.service = comment.NewService(comment.ServiceDeps{
		Repository:    s.mockCommentRepo,
		AppealService: appealService,
		Notifier:      s.mockNotifier,
		AuditLogger:   s.mockAuditLogger,
		Logger:        log.NewNoop(),
	})
}

func TestService(t *testing.T) {
	suite.Run(t, new(ServiceTestSuite))
}

func (s *ServiceTestSuite) TestCreate() {
	s.Run("should return list of comments on success", func() {
		appealID := uuid.New().String()
		appealRequestor := "requestor@example.com"
		approvers := []string{"approver1@example.com", "approver2@example.com"}
		commentParticipant := "participant@example.com"
		dummyAppeal := &domain.Appeal{
			ID:        appealID,
			CreatedBy: appealRequestor,
			Approvals: []*domain.Approval{
				{
					Status:    domain.ApprovalStatusApproved,
					Approvers: []string{"approver.x@example.com"},
				},
				{
					Status:    domain.ApprovalStatusPending,
					Approvers: approvers,
				},
				{
					Status:    domain.ApprovalStatusBlocked,
					Approvers: []string{"approver.x@example.com"},
				},
			},
			Resource: &domain.Resource{},
		}
		s.mockAppealRepo.EXPECT().
			GetByID(mock.MatchedBy(func(ctx context.Context) bool { return true }), appealID).
			Return(dummyAppeal, nil)
		defer s.mockAppealRepo.AssertExpectations(s.T())

		s.mockCommentRepo.EXPECT().
			Create(mock.MatchedBy(func(ctx context.Context) bool { return true }), mock.AnythingOfType("*domain.Comment")).
			Return(nil).
			Run(func(_a0 context.Context, _a1 *domain.Comment) {
				s.Equal(appealID, _a1.AppealID)
				s.NotEmpty(_a1.CreatedBy)
				s.NotEmpty(_a1.Body)
			})

		newComment := &domain.Comment{
			AppealID:  appealID,
			CreatedBy: "comment.creator@example.com",
			Body:      "test comment content",
		}
		appealComments := []*domain.Comment{
			{CreatedBy: commentParticipant},
			newComment,
		}
		s.mockCommentRepo.EXPECT().
			List(mock.MatchedBy(func(ctx context.Context) bool { return true }), domain.ListCommentsFilter{AppealID: appealID}).
			Return(appealComments, nil)
		// defer s.mockRepo.AssertExpectations(s.T())

		s.mockNotifier.EXPECT().
			Notify(mock.MatchedBy(func(ctx context.Context) bool { return true }), mock.AnythingOfType("[]domain.Notification")).
			Return(nil).
			Run(func(_a0 context.Context, notifications []domain.Notification) {
				// verify recipients
				expectedRecipients := map[string]bool{
					appealRequestor:    true,
					approvers[0]:       true,
					approvers[1]:       true,
					commentParticipant: true,
				}
				actualRecipients := map[string]bool{}
				for _, n := range notifications {
					actualRecipients[n.User] = true
				}
				s.Equal(expectedRecipients, actualRecipients)

				// verify notification message/variables
				expectedNotifMsg := domain.NotificationMessage{
					Type: domain.NotificationTypeNewComment,
					Variables: map[string]interface{}{
						"appeal_id":          appealID,
						"appeal_created_by":  appealRequestor,
						"resource_name":      fmt.Sprintf("%s (%s: %s)", dummyAppeal.Resource.Name, dummyAppeal.Resource.ProviderType, dummyAppeal.Resource.URN),
						"comment_id":         newComment.ID,
						"comment_created_by": newComment.CreatedBy,
						"body":               newComment.Body,
					},
				}
				for _, n := range notifications {
					s.Equal(expectedNotifMsg, n.Message)
				}
			})

		s.mockAuditLogger.EXPECT().
			Log(mock.MatchedBy(func(ctx context.Context) bool { return true }), comment.AuditKeyCreate, newComment).
			Return(nil)

		actualErr := s.service.Create(context.Background(), newComment)
		s.NoError(actualErr)

		time.Sleep(2 * time.Second) // wait for async actions to complete
		s.mockCommentRepo.AssertExpectations(s.T())
		s.mockNotifier.AssertExpectations(s.T())
		s.mockAuditLogger.AssertExpectations(s.T())
	})
}

func (s *ServiceTestSuite) TestList() {
	s.Run("should return list of comments on success", func() {
		appealID := uuid.New().String()
		s.mockAppealRepo.EXPECT().
			GetByID(mock.MatchedBy(func(ctx context.Context) bool { return true }), appealID).
			Return(&domain.Appeal{}, nil)

		expectedComments := []*domain.Comment{
			{ID: uuid.New().String(), AppealID: appealID, CreatedBy: "user1@example.com", Body: "comment 1"},
			{ID: uuid.New().String(), AppealID: appealID, CreatedBy: "user2@example.com", Body: "comment 2"},
		}
		s.mockCommentRepo.EXPECT().
			List(mock.MatchedBy(func(ctx context.Context) bool { return true }), mock.AnythingOfType("domain.ListCommentsFilter")).
			Return(expectedComments, nil).
			Run(func(_a0 context.Context, filter domain.ListCommentsFilter) {
				s.Equal(appealID, filter.AppealID)
				defaultSort := []string{"created_at"}
				s.Equal(defaultSort, filter.OrderBy)
			})

		actualComments, actualErr := s.service.List(context.Background(), domain.ListCommentsFilter{AppealID: appealID})
		s.NoError(actualErr)
		s.Equal(expectedComments, actualComments)
	})
}
