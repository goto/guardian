package appeal_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/goto/guardian/core/appeal"
	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestCreateComment(t *testing.T) {
	t.Run("should return list of comments on success", func(t *testing.T) {
		h := newServiceTestHelper()

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
		h.mockRepository.EXPECT().
			GetByID(h.ctxMatcher, appealID).
			Return(dummyAppeal, nil)

		h.mockCommentRepo.EXPECT().
			Create(h.ctxMatcher, mock.AnythingOfType("*domain.Comment")).
			Return(nil).
			Run(func(_a0 context.Context, _a1 *domain.Comment) {
				assert.Equal(t, appeal.CommentParentTypeAppeal, _a1.ParentType)
				assert.Equal(t, appealID, _a1.ParentID)
				assert.NotEmpty(t, _a1.CreatedBy)
				assert.NotEmpty(t, _a1.Body)
			})

		newComment := &domain.Comment{
			ParentID:  appealID,
			CreatedBy: "comment.creator@example.com",
			Body:      "test comment content",
		}
		appealComments := []*domain.Comment{
			{CreatedBy: commentParticipant},
			newComment,
		}
		h.mockCommentRepo.EXPECT().
			List(h.ctxMatcher, mock.MatchedBy(func(filter domain.ListCommentsFilter) bool {
				return filter.ParentType == appeal.CommentParentTypeAppeal && filter.ParentID == appealID
			})).
			Return(appealComments, nil)

		h.mockNotifier.EXPECT().
			Notify(h.ctxMatcher, mock.AnythingOfType("[]domain.Notification")).
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
				assert.Equal(t, expectedRecipients, actualRecipients)

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
					assert.Equal(t, expectedNotifMsg, n.Message)
				}
			})
		h.mockAuditLogger.EXPECT().
			Log(h.ctxMatcher, mock.Anything, mock.Anything).
			Return(nil)

		actualErr := h.service.CreateComment(context.Background(), newComment)
		assert.NoError(t, actualErr)

		time.Sleep(2 * time.Second) // wait for async actions to complete
		h.assertExpectations(t)
	})
}

func TestListComments(t *testing.T) {
	t.Run("should return list of comments on success", func(t *testing.T) {
		h := newServiceTestHelper()
		defer h.assertExpectations(t)
		appealID := uuid.New().String()
		h.mockRepository.EXPECT().
			GetByID(h.ctxMatcher, appealID).
			Return(&domain.Appeal{}, nil)

		expectedComments := []*domain.Comment{
			{ID: uuid.New().String(), ParentType: appeal.CommentParentTypeAppeal, ParentID: appealID, CreatedBy: "user1@example.com", Body: "comment 1"},
			{ID: uuid.New().String(), ParentType: appeal.CommentParentTypeAppeal, ParentID: appealID, CreatedBy: "user2@example.com", Body: "comment 2"},
		}
		h.mockCommentRepo.EXPECT().
			List(h.ctxMatcher, mock.AnythingOfType("domain.ListCommentsFilter")).
			Return(expectedComments, nil).
			Run(func(_a0 context.Context, filter domain.ListCommentsFilter) {
				assert.Equal(t, appeal.CommentParentTypeAppeal, filter.ParentType)
				assert.Equal(t, appealID, filter.ParentID)
			})

		actualComments, actualErr := h.service.ListComments(context.Background(), domain.ListCommentsFilter{ParentID: appealID})
		assert.NoError(t, actualErr)
		assert.Equal(t, expectedComments, actualComments)
	})
}
