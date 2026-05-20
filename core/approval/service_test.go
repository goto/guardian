package approval_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/goto/guardian/core/approval"
	approvalmocks "github.com/goto/guardian/core/approval/mocks"
	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type ServiceTestSuite struct {
	suite.Suite
	mockRepository    *approvalmocks.Repository
	mockPolicyService *approvalmocks.PolicyService

	service *approval.Service
}

func TestService(t *testing.T) {
	suite.Run(t, new(ServiceTestSuite))
}

func (s *ServiceTestSuite) SetupTest() {
	s.mockRepository = new(approvalmocks.Repository)
	s.mockPolicyService = new(approvalmocks.PolicyService)

	s.service = approval.NewService(approval.ServiceDeps{
		s.mockRepository,
		s.mockPolicyService,
	})
}

func (s *ServiceTestSuite) TestListApprovals() {
	s.Run("should return error if got error from repository", func() {
		expectedError := errors.New("repository error")
		s.mockRepository.EXPECT().
			ListApprovals(mock.MatchedBy(func(ctx context.Context) bool { return true }), mock.Anything).
			Return(nil, expectedError).Once()

		actualApprovals, actualError := s.service.ListApprovals(context.Background(), &domain.ListApprovalsFilter{})

		s.Nil(actualApprovals)
		s.EqualError(actualError, expectedError.Error())
	})

	s.Run("should return approvals from repository", func() {
		expectedApprovals := []*domain.Approval{
			{
				ID: uuid.New().String(),
			},
		}
		s.mockRepository.EXPECT().
			ListApprovals(mock.MatchedBy(func(ctx context.Context) bool { return true }), mock.Anything).
			Return(expectedApprovals, nil).Once()

		actualApprovals, actualError := s.service.ListApprovals(context.Background(), &domain.ListApprovalsFilter{})

		s.Equal(expectedApprovals, actualApprovals)
		s.NoError(actualError)
	})
}

func (s *ServiceTestSuite) TestGetApprovalsTotalCount() {
	s.Run("should return error if got error from repository", func() {
		expectedError := errors.New("repository error")
		s.mockRepository.EXPECT().
			GetApprovalsTotalCount(mock.MatchedBy(func(ctx context.Context) bool { return true }), mock.Anything).
			Return(0, expectedError).Once()

		actualCount, actualError := s.service.GetApprovalsTotalCount(context.Background(), &domain.ListApprovalsFilter{})

		s.Zero(actualCount)
		s.EqualError(actualError, expectedError.Error())
	})

	s.Run("should return approvals count from repository", func() {
		expectedCount := int64(1)
		s.mockRepository.EXPECT().
			GetApprovalsTotalCount(mock.MatchedBy(func(ctx context.Context) bool { return true }), mock.Anything).
			Return(expectedCount, nil).Once()

		actualCount, actualError := s.service.GetApprovalsTotalCount(context.Background(), &domain.ListApprovalsFilter{})

		s.Equal(expectedCount, actualCount)
		s.NoError(actualError)
	})
}

func (s *ServiceTestSuite) TestBulkInsert() {
	s.Run("should return error if got error from repository", func() {
		expectedError := errors.New("repository error")
		s.mockRepository.EXPECT().
			BulkInsert(mock.MatchedBy(func(ctx context.Context) bool { return true }), mock.Anything).
			Return(expectedError).Once()

		actualError := s.service.BulkInsert(context.Background(), []*domain.Approval{})

		s.EqualError(actualError, expectedError.Error())
	})
}

func (s *ServiceTestSuite) TestAddApprover() {
	s.Run("should return nil error on success", func() {
		expectedApprover := &domain.Approver{
			ApprovalID: uuid.New().String(),
			Email:      "user@example.com",
		}
		s.mockRepository.EXPECT().AddApprover(mock.Anything, expectedApprover).Return(nil)

		err := s.service.AddApprover(context.Background(), expectedApprover.ApprovalID, expectedApprover.Email)

		s.NoError(err)
		s.mockRepository.AssertExpectations(s.T())
	})

	s.Run("should return error if repository returns an error", func() {
		expectedError := errors.New("unexpected error")
		s.mockRepository.EXPECT().AddApprover(mock.Anything, mock.Anything).Return(expectedError)

		err := s.service.AddApprover(context.Background(), "", "")

		s.ErrorIs(err, expectedError)
		s.mockRepository.AssertExpectations(s.T())
	})
}

func (s *ServiceTestSuite) TestListApprovals_WithPreviousGrant() {
	accountID := "user@example.com"
	resourceID := uuid.New().String()
	role := "viewer"

	newApproval := func() *domain.Approval {
		return &domain.Approval{
			ID: uuid.New().String(),
			Appeal: &domain.Appeal{
				AccountID:  accountID,
				ResourceID: resourceID,
				Role:       role,
			},
		}
	}

	s.Run("should not call grant service when WithPreviousGrant is false", func() {
		s.SetupTest()
		mockGrantService := new(approvalmocks.GrantService)
		s.service.SetGrantService(mockGrantService)

		expected := []*domain.Approval{newApproval()}
		s.mockRepository.EXPECT().
			ListApprovals(mock.Anything, mock.Anything).
			Return(expected, nil).Once()

		got, err := s.service.ListApprovals(context.Background(), &domain.ListApprovalsFilter{
			WithPreviousGrant: false,
		})

		s.NoError(err)
		s.Equal(expected, got)
		mockGrantService.AssertNotCalled(s.T(), "List", mock.Anything, mock.Anything)
	})

	s.Run("should populate previous_grant_expiration_date with the latest grant per appeal", func() {
		s.SetupTest()
		mockGrantService := new(approvalmocks.GrantService)
		s.service.SetGrantService(mockGrantService)

		latest := time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC)
		older := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

		approval1 := newApproval()
		approval2 := newApproval()
		s.mockRepository.EXPECT().
			ListApprovals(mock.Anything, mock.Anything).
			Return([]*domain.Approval{approval1, approval2}, nil).Once()

		// Grant service returns two grants for the same (account_id, resource_id, role) triple,
		// in created_at DESC order. The first one wins.
		mockGrantService.EXPECT().
			List(mock.Anything, mock.MatchedBy(func(f domain.ListGrantsFilter) bool {
				return len(f.AccountIDs) == 1 && f.AccountIDs[0] == accountID &&
					len(f.ResourceIDs) == 1 && f.ResourceIDs[0] == resourceID &&
					len(f.Roles) == 1 && f.Roles[0] == role &&
					len(f.OrderBy) == 1 && f.OrderBy[0] == "created_at:desc"
			})).
			Return([]domain.Grant{
				{AccountID: accountID, ResourceID: resourceID, Role: role, ExpirationDate: &latest},
				{AccountID: accountID, ResourceID: resourceID, Role: role, ExpirationDate: &older},
			}, nil).Once()

		got, err := s.service.ListApprovals(context.Background(), &domain.ListApprovalsFilter{
			WithPreviousGrant: true,
		})

		s.NoError(err)
		s.Require().Len(got, 2)
		s.Require().NotNil(got[0].PreviousGrantExpirationDate)
		s.Equal(latest, *got[0].PreviousGrantExpirationDate)
		s.Require().NotNil(got[1].PreviousGrantExpirationDate)
		s.Equal(latest, *got[1].PreviousGrantExpirationDate)
	})

	s.Run("should leave previous_grant_expiration_date nil when no grant matches", func() {
		s.SetupTest()
		mockGrantService := new(approvalmocks.GrantService)
		s.service.SetGrantService(mockGrantService)

		approval := newApproval()
		s.mockRepository.EXPECT().
			ListApprovals(mock.Anything, mock.Anything).
			Return([]*domain.Approval{approval}, nil).Once()
		mockGrantService.EXPECT().
			List(mock.Anything, mock.Anything).
			Return([]domain.Grant{}, nil).Once()

		got, err := s.service.ListApprovals(context.Background(), &domain.ListApprovalsFilter{
			WithPreviousGrant: true,
		})

		s.NoError(err)
		s.Require().Len(got, 1)
		s.Nil(got[0].PreviousGrantExpirationDate)
	})

	s.Run("should skip grant matching when grant has no expiration date", func() {
		s.SetupTest()
		mockGrantService := new(approvalmocks.GrantService)
		s.service.SetGrantService(mockGrantService)

		approval := newApproval()
		s.mockRepository.EXPECT().
			ListApprovals(mock.Anything, mock.Anything).
			Return([]*domain.Approval{approval}, nil).Once()
		mockGrantService.EXPECT().
			List(mock.Anything, mock.Anything).
			Return([]domain.Grant{
				{AccountID: accountID, ResourceID: resourceID, Role: role, ExpirationDate: nil},
			}, nil).Once()

		got, err := s.service.ListApprovals(context.Background(), &domain.ListApprovalsFilter{
			WithPreviousGrant: true,
		})

		s.NoError(err)
		s.Require().Len(got, 1)
		s.Nil(got[0].PreviousGrantExpirationDate)
	})

	s.Run("should skip approvals whose Appeal is nil without crashing", func() {
		s.SetupTest()
		mockGrantService := new(approvalmocks.GrantService)
		s.service.SetGrantService(mockGrantService)

		approvalWithAppeal := newApproval()
		approvalWithoutAppeal := &domain.Approval{ID: uuid.New().String()}
		s.mockRepository.EXPECT().
			ListApprovals(mock.Anything, mock.Anything).
			Return([]*domain.Approval{approvalWithAppeal, approvalWithoutAppeal}, nil).Once()

		exp := time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC)
		mockGrantService.EXPECT().
			List(mock.Anything, mock.Anything).
			Return([]domain.Grant{
				{AccountID: accountID, ResourceID: resourceID, Role: role, ExpirationDate: &exp},
			}, nil).Once()

		got, err := s.service.ListApprovals(context.Background(), &domain.ListApprovalsFilter{
			WithPreviousGrant: true,
		})

		s.NoError(err)
		s.Require().Len(got, 2)
		s.Require().NotNil(got[0].PreviousGrantExpirationDate)
		s.Equal(exp, *got[0].PreviousGrantExpirationDate)
		s.Nil(got[1].PreviousGrantExpirationDate)
	})

	s.Run("should return error if grant service fails", func() {
		s.SetupTest()
		mockGrantService := new(approvalmocks.GrantService)
		s.service.SetGrantService(mockGrantService)

		s.mockRepository.EXPECT().
			ListApprovals(mock.Anything, mock.Anything).
			Return([]*domain.Approval{newApproval()}, nil).Once()
		expectedErr := errors.New("grant service error")
		mockGrantService.EXPECT().
			List(mock.Anything, mock.Anything).
			Return(nil, expectedErr).Once()

		got, err := s.service.ListApprovals(context.Background(), &domain.ListApprovalsFilter{
			WithPreviousGrant: true,
		})

		s.Nil(got)
		s.EqualError(err, expectedErr.Error())
	})

	s.Run("should skip grant lookup if grant service is not configured", func() {
		s.SetupTest()
		// no SetGrantService call

		expected := []*domain.Approval{newApproval()}
		s.mockRepository.EXPECT().
			ListApprovals(mock.Anything, mock.Anything).
			Return(expected, nil).Once()

		got, err := s.service.ListApprovals(context.Background(), &domain.ListApprovalsFilter{
			WithPreviousGrant: true,
		})

		s.NoError(err)
		s.Equal(expected, got)
		s.Nil(got[0].PreviousGrantExpirationDate)
	})

	s.Run("should skip grant lookup if there are no approvals", func() {
		s.SetupTest()
		mockGrantService := new(approvalmocks.GrantService)
		s.service.SetGrantService(mockGrantService)

		s.mockRepository.EXPECT().
			ListApprovals(mock.Anything, mock.Anything).
			Return([]*domain.Approval{}, nil).Once()

		got, err := s.service.ListApprovals(context.Background(), &domain.ListApprovalsFilter{
			WithPreviousGrant: true,
		})

		s.NoError(err)
		s.Empty(got)
		mockGrantService.AssertNotCalled(s.T(), "List", mock.Anything, mock.Anything)
	})
}

func (s *ServiceTestSuite) TestDeleteApprover() {
	s.Run("should return nil error on success", func() {
		approvalID := uuid.New().String()
		approverEmail := "user@example.com"

		s.mockRepository.EXPECT().DeleteApprover(mock.MatchedBy(func(ctx context.Context) bool { return true }), approvalID, approverEmail).Return(nil)

		err := s.service.DeleteApprover(context.Background(), approvalID, approverEmail)

		s.NoError(err)
		s.mockRepository.AssertExpectations(s.T())
	})

	s.Run("should return error if repository returns an error", func() {
		expectedError := errors.New("unexpected error")
		s.mockRepository.EXPECT().DeleteApprover(mock.MatchedBy(func(ctx context.Context) bool { return true }), mock.Anything, mock.Anything).Return(expectedError)

		err := s.service.DeleteApprover(context.Background(), "", "")

		s.ErrorIs(err, expectedError)
		s.mockRepository.AssertExpectations(s.T())
	})
}
