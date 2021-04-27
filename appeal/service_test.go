package appeal_test

import (
	"errors"
	"testing"
	"time"

	"github.com/odpf/guardian/appeal"
	"github.com/odpf/guardian/domain"
	"github.com/odpf/guardian/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type ServiceTestSuite struct {
	suite.Suite
	mockRepository             *mocks.AppealRepository
	mockApprovalService        *mocks.ApprovalService
	mockResourceService        *mocks.ResourceService
	mockProviderService        *mocks.ProviderService
	mockPolicyService          *mocks.PolicyService
	mockIdentityManagerService *mocks.IdentityManagerService

	service *appeal.Service
}

func (s *ServiceTestSuite) SetupTest() {
	s.mockRepository = new(mocks.AppealRepository)
	s.mockApprovalService = new(mocks.ApprovalService)
	s.mockResourceService = new(mocks.ResourceService)
	s.mockProviderService = new(mocks.ProviderService)
	s.mockPolicyService = new(mocks.PolicyService)
	s.mockIdentityManagerService = new(mocks.IdentityManagerService)

	s.service = appeal.NewService(
		s.mockRepository,
		s.mockApprovalService,
		s.mockResourceService,
		s.mockProviderService,
		s.mockPolicyService,
		s.mockIdentityManagerService,
	)
}

func (s *ServiceTestSuite) TestGetByID() {
	s.Run("should return error if id is empty/0", func() {
		expectedError := appeal.ErrAppealIDEmptyParam

		actualResult, actualError := s.service.GetByID(0)

		s.Nil(actualResult)
		s.EqualError(actualError, expectedError.Error())
	})

	s.Run("should return error if got any from repository", func() {
		expectedError := errors.New("repository error")
		s.mockRepository.On("GetByID", mock.Anything).Return(nil, expectedError).Once()

		actualResult, actualError := s.service.GetByID(1)

		s.Nil(actualResult)
		s.EqualError(actualError, expectedError.Error())
	})

	s.Run("should return record on success", func() {
		expectedID := uint(1)
		expectedResult := &domain.Appeal{
			ID: uint(expectedID),
		}
		s.mockRepository.On("GetByID", expectedID).Return(expectedResult, nil).Once()

		actualResult, actualError := s.service.GetByID(expectedID)

		s.Equal(expectedResult, actualResult)
		s.Nil(actualError)
	})
}

func (s *ServiceTestSuite) TestFind() {
	s.Run("should return error if got any from repository", func() {
		expectedError := errors.New("unexpected repository error")
		s.mockRepository.On("Find", mock.Anything).Return(nil, expectedError).Once()

		actualResult, actualError := s.service.Find(map[string]interface{}{})

		s.Nil(actualResult)
		s.EqualError(actualError, expectedError.Error())
	})

	s.Run("should return records on success", func() {
		expectedFilters := map[string]interface{}{
			"user": "user@email.com",
		}
		expectedResult := []*domain.Appeal{
			{
				ID:         1,
				ResourceID: 1,
				User:       "user@email.com",
				Role:       "viewer",
			},
		}
		s.mockRepository.On("Find", expectedFilters).Return(expectedResult, nil).Once()

		actualResult, actualError := s.service.Find(expectedFilters)

		s.Equal(expectedResult, actualResult)
		s.Nil(actualError)
	})
}

func (s *ServiceTestSuite) TestCreate() {
	s.Run("should return error if got error from resource service", func() {
		expectedError := errors.New("resource service error")
		s.mockResourceService.On("Find", mock.Anything).Return(nil, expectedError).Once()

		actualError := s.service.Create([]*domain.Appeal{})

		s.EqualError(actualError, expectedError.Error())
	})

	s.Run("should return error if got error from provider service", func() {
		expectedResources := []*domain.Resource{}
		s.mockResourceService.On("Find", mock.Anything).Return(expectedResources, nil).Once()
		expectedError := errors.New("provider service error")
		s.mockProviderService.On("Find").Return(nil, expectedError).Once()

		actualError := s.service.Create([]*domain.Appeal{})

		s.EqualError(actualError, expectedError.Error())
	})

	s.Run("should return error if got error from policy service", func() {
		expectedResources := []*domain.Resource{}
		expectedProviders := []*domain.Provider{}
		s.mockResourceService.On("Find", mock.Anything).Return(expectedResources, nil).Once()
		s.mockProviderService.On("Find").Return(expectedProviders, nil).Once()
		expectedError := errors.New("policy service error")
		s.mockPolicyService.On("Find").Return(nil, expectedError).Once()

		actualError := s.service.Create([]*domain.Appeal{})

		s.EqualError(actualError, expectedError.Error())
	})

	s.Run("should return error if got error from repository", func() {
		expectedResources := []*domain.Resource{}
		expectedProviders := []*domain.Provider{}
		expectedPolicies := []*domain.Policy{}
		s.mockResourceService.On("Find", mock.Anything).Return(expectedResources, nil).Once()
		s.mockProviderService.On("Find").Return(expectedProviders, nil).Once()
		s.mockPolicyService.On("Find").Return(expectedPolicies, nil).Once()
		expectedError := errors.New("repository error")
		s.mockRepository.On("BulkInsert", mock.Anything).Return(expectedError).Once()

		actualError := s.service.Create([]*domain.Appeal{})

		s.EqualError(actualError, expectedError.Error())
	})

	user := "test@email.com"
	resourceIDs := []uint{1, 2}
	resources := []*domain.Resource{}
	for _, id := range resourceIDs {
		resources = append(resources, &domain.Resource{
			ID:           id,
			Type:         "resource_type_1",
			ProviderType: "provider_type",
			ProviderURN:  "provider1",
			Details: map[string]interface{}{
				"owner": []string{"resource.owner@email.com"},
			},
		})
	}
	providers := []*domain.Provider{
		{
			ID:   1,
			Type: "provider_type",
			URN:  "provider1",
			Config: &domain.ProviderConfig{
				Resources: []*domain.ResourceConfig{
					{
						Type: "resource_type_1",
						Policy: &domain.PolicyConfig{
							ID:      "policy_1",
							Version: 1,
						},
					},
				},
			},
		},
	}
	policies := []*domain.Policy{
		{
			ID:      "policy_1",
			Version: 1,
			Steps: []*domain.Step{
				{
					Name:      "step_1",
					Approvers: "$resource.details.owner",
				},
				{
					Name:      "step_2",
					Approvers: "$user_approvers",
				},
			},
		},
	}
	expectedAppealsInsertionParam := []*domain.Appeal{}
	for _, r := range resourceIDs {
		expectedAppealsInsertionParam = append(expectedAppealsInsertionParam, &domain.Appeal{
			ResourceID:    r,
			PolicyID:      "policy_1",
			PolicyVersion: 1,
			Status:        domain.AppealStatusPending,
			User:          user,
			Approvals: []*domain.Approval{
				{
					Name:          "step_1",
					Index:         0,
					Status:        domain.ApprovalStatusPending,
					PolicyID:      "policy_1",
					PolicyVersion: 1,
					Approvers:     []string{"resource.owner@email.com"},
				},
				{
					Name:          "step_2",
					Index:         1,
					Status:        domain.ApprovalStatusPending,
					PolicyID:      "policy_1",
					PolicyVersion: 1,
					Approvers:     []string{"user.approver@email.com"},
				},
			},
		})
	}
	expectedResult := []*domain.Appeal{
		{
			ID:            1,
			ResourceID:    1,
			PolicyID:      "policy_1",
			PolicyVersion: 1,
			Status:        domain.AppealStatusPending,
			User:          user,
			Approvals: []*domain.Approval{
				{
					ID:            1,
					Name:          "step_1",
					Index:         0,
					Status:        domain.ApprovalStatusPending,
					PolicyID:      "policy_1",
					PolicyVersion: 1,
					Approvers:     []string{"resource.owner@email.com"},
				},
				{
					ID:            2,
					Name:          "step_2",
					Index:         1,
					Status:        domain.ApprovalStatusPending,
					PolicyID:      "policy_1",
					PolicyVersion: 1,
					Approvers:     []string{"user.approver@email.com"},
				},
			},
		},
		{
			ID:            2,
			ResourceID:    2,
			PolicyID:      "policy_1",
			PolicyVersion: 1,
			Status:        domain.AppealStatusPending,
			User:          user,
			Approvals: []*domain.Approval{
				{
					ID:            1,
					Name:          "step_1",
					Index:         0,
					Status:        domain.ApprovalStatusPending,
					PolicyID:      "policy_1",
					PolicyVersion: 1,
					Approvers:     []string{"resource.owner@email.com"},
				},
				{
					ID:            2,
					Name:          "step_2",
					Index:         1,
					Status:        domain.ApprovalStatusPending,
					PolicyID:      "policy_1",
					PolicyVersion: 1,
					Approvers:     []string{"user.approver@email.com"},
				},
			},
		},
	}

	s.Run("should return appeals on success", func() {
		expectedFilters := map[string]interface{}{"ids": resourceIDs}
		s.mockResourceService.On("Find", expectedFilters).Return(resources, nil).Once()
		s.mockProviderService.On("Find").Return(providers, nil).Once()
		s.mockPolicyService.On("Find").Return(policies, nil).Once()
		expectedUserApprovers := []string{"user.approver@email.com"}
		s.mockIdentityManagerService.On("GetUserApproverEmails", user).Return(expectedUserApprovers, nil)
		s.mockRepository.
			On("BulkInsert", expectedAppealsInsertionParam).
			Return(nil).
			Run(func(args mock.Arguments) {
				appeals := args.Get(0).([]*domain.Appeal)
				for i, a := range appeals {
					a.ID = expectedResult[i].ID
					for j, approval := range a.Approvals {
						approval.ID = expectedResult[i].Approvals[j].ID
					}
				}
			}).
			Once()

		appeals := []*domain.Appeal{
			{
				User:       user,
				ResourceID: 1,
			},
			{
				User:       user,
				ResourceID: 2,
			},
		}
		actualError := s.service.Create(appeals)

		s.Equal(expectedResult, appeals)
		s.Nil(actualError)
	})
}

func (s *ServiceTestSuite) TestMakeAction() {
	timeNow := time.Now()
	appeal.TimeNow = func() time.Time {
		return timeNow
	}
	s.Run("should return error if approval action parameter is invalid", func() {
		invalidApprovalActionParameters := []domain.ApprovalAction{
			{
				ApprovalName: "approval_1",
				Actor:        "user@email.com",
				Action:       "name",
			},
			{
				AppealID: 1,
				Actor:    "user@email.com",
				Action:   "name",
			},
			{
				AppealID:     1,
				ApprovalName: "approval_1",
				Actor:        "invalidemail",
				Action:       "name",
			},
			{
				AppealID:     1,
				ApprovalName: "approval_1",
				Action:       "name",
			},
			{
				AppealID:     1,
				ApprovalName: "approval_1",
				Actor:        "user@email.com",
			},
		}

		for _, param := range invalidApprovalActionParameters {
			actualResult, actualError := s.service.MakeAction(param)

			s.Nil(actualResult)
			s.Error(actualError)
		}
	})

	validApprovalActionParam := domain.ApprovalAction{
		AppealID:     1,
		ApprovalName: "approval_1",
		Actor:        "user@email.com",
		Action:       "approve",
	}

	s.Run("should return error if got any from repository while getting appeal details", func() {
		expectedError := errors.New("repository error")
		s.mockRepository.On("GetByID", mock.Anything).Return(nil, expectedError).Once()

		actualResult, actualError := s.service.MakeAction(validApprovalActionParam)

		s.Nil(actualResult)
		s.EqualError(actualError, expectedError.Error())
	})

	s.Run("should return nil and nil error if appeal not found", func() {
		s.mockRepository.On("GetByID", validApprovalActionParam.AppealID).Return(nil, nil).Once()

		actualResult, actualError := s.service.MakeAction(validApprovalActionParam)

		s.Nil(actualResult)
		s.Nil(actualError)
	})

	s.Run("should return error based on statuses conditions", func() {
		testCases := []struct {
			name          string
			appealStatus  string
			approvals     []*domain.Approval
			expectedError error
		}{
			{
				name:          "appeal not eligible, status: active",
				appealStatus:  domain.AppealStatusActive,
				expectedError: appeal.ErrAppealStatusApproved,
			},
			{
				name:          "appeal not eligible, status: rejected",
				appealStatus:  domain.AppealStatusRejected,
				expectedError: appeal.ErrAppealStatusRejected,
			},
			{
				name:          "appeal not eligible, status: terminated",
				appealStatus:  domain.AppealStatusTerminated,
				expectedError: appeal.ErrAppealStatusTerminated,
			},
			{
				name:          "invalid appeal status",
				appealStatus:  "invalidstatus",
				expectedError: appeal.ErrAppealStatusUnrecognized,
			},
			{
				name:         "previous approval step still on pending",
				appealStatus: domain.AppealStatusPending,
				approvals: []*domain.Approval{
					{
						Name:   "approval_0",
						Status: domain.ApprovalStatusPending,
					},
					{
						Name:   "approval_1",
						Status: domain.ApprovalStatusPending,
					},
				},
				expectedError: appeal.ErrApprovalDependencyIsPending,
			},
			{
				name:         "found one previous approval is reject",
				appealStatus: domain.AppealStatusPending,
				approvals: []*domain.Approval{
					{
						Name:   "approval_0",
						Status: domain.ApprovalStatusRejected,
					},
					{
						Name:   "approval_1",
						Status: domain.ApprovalStatusPending,
					},
				},
				expectedError: appeal.ErrAppealStatusRejected,
			},
			{
				name:         "invalid approval status",
				appealStatus: domain.AppealStatusPending,
				approvals: []*domain.Approval{
					{
						Name:   "approval_0",
						Status: "invalidstatus",
					},
					{
						Name:   "approval_1",
						Status: domain.ApprovalStatusPending,
					},
				},
				expectedError: appeal.ErrApprovalStatusUnrecognized,
			},
			{
				name:         "approval step already approved",
				appealStatus: domain.AppealStatusPending,
				approvals: []*domain.Approval{
					{
						Name:   "approval_0",
						Status: domain.ApprovalStatusApproved,
					},
					{
						Name:   "approval_1",
						Status: domain.ApprovalStatusApproved,
					},
				},
				expectedError: appeal.ErrApprovalStatusApproved,
			},
			{
				name:         "approval step already rejected",
				appealStatus: domain.AppealStatusPending,
				approvals: []*domain.Approval{
					{
						Name:   "approval_0",
						Status: domain.ApprovalStatusApproved,
					},
					{
						Name:   "approval_1",
						Status: domain.ApprovalStatusRejected,
					},
				},
				expectedError: appeal.ErrApprovalStatusRejected,
			},
			{
				name:         "approval step already skipped",
				appealStatus: domain.AppealStatusPending,
				approvals: []*domain.Approval{
					{
						Name:   "approval_0",
						Status: domain.ApprovalStatusApproved,
					},
					{
						Name:   "approval_1",
						Status: domain.ApprovalStatusSkipped,
					},
				},
				expectedError: appeal.ErrApprovalStatusSkipped,
			},
			{
				name:         "invalid approval status",
				appealStatus: domain.AppealStatusPending,
				approvals: []*domain.Approval{
					{
						Name:   "approval_0",
						Status: domain.ApprovalStatusApproved,
					},
					{
						Name:   "approval_1",
						Status: "invalidstatus",
					},
				},
				expectedError: appeal.ErrApprovalStatusUnrecognized,
			},
			{
				name:         "user doesn't have permission",
				appealStatus: domain.AppealStatusPending,
				approvals: []*domain.Approval{
					{
						Name:   "approval_0",
						Status: domain.ApprovalStatusApproved,
					},
					{
						Name:      "approval_1",
						Status:    domain.ApprovalStatusPending,
						Approvers: []string{"another.user@email.com"},
					},
				},
				expectedError: appeal.ErrActionForbidden,
			},
			{
				name:         "approval step not found",
				appealStatus: domain.AppealStatusPending,
				approvals: []*domain.Approval{
					{
						Name:   "approval_0",
						Status: domain.ApprovalStatusApproved,
					},
					{
						Name:   "approval_x",
						Status: domain.ApprovalStatusApproved,
					},
				},
				expectedError: appeal.ErrApprovalNameNotFound,
			},
		}

		for _, tc := range testCases {
			expectedAppeal := &domain.Appeal{
				ID:        validApprovalActionParam.AppealID,
				Status:    tc.appealStatus,
				Approvals: tc.approvals,
			}
			s.mockRepository.On("GetByID", validApprovalActionParam.AppealID).Return(expectedAppeal, nil).Once()

			actualResult, actualError := s.service.MakeAction(validApprovalActionParam)

			s.Nil(actualResult)
			s.EqualError(actualError, tc.expectedError.Error())
		}
	})

	s.Run("should return error if got any from repository while updating appeal", func() {
		expectedAppeal := &domain.Appeal{
			ID:     validApprovalActionParam.AppealID,
			Status: domain.AppealStatusPending,
			Approvals: []*domain.Approval{
				{
					Name:   "approval_0",
					Status: domain.ApprovalStatusApproved,
				},
				{
					Name:      "approval_1",
					Status:    domain.ApprovalStatusPending,
					Approvers: []string{"user@email.com"},
				},
			},
		}
		s.mockRepository.On("GetByID", validApprovalActionParam.AppealID).Return(expectedAppeal, nil).Once()
		expectedError := errors.New("repository error")
		s.mockProviderService.On("GrantAccess", expectedAppeal).Return(nil).Once()
		s.mockRepository.On("Update", mock.Anything).Return(expectedError).Once()
		s.mockProviderService.On("RevokeAccess", expectedAppeal).Return(nil).Once()

		actualResult, actualError := s.service.MakeAction(validApprovalActionParam)

		s.Nil(actualResult)
		s.EqualError(actualError, expectedError.Error())
	})

	s.Run("should return updated appeal on success", func() {
		user := "user@email.com"
		testCases := []struct {
			name                   string
			expectedApprovalAction domain.ApprovalAction
			expectedAppealDetails  *domain.Appeal
			expectedResult         *domain.Appeal
		}{
			{
				name:                   "approve",
				expectedApprovalAction: validApprovalActionParam,
				expectedAppealDetails: &domain.Appeal{
					ID:     validApprovalActionParam.AppealID,
					Status: domain.AppealStatusPending,
					Approvals: []*domain.Approval{
						{
							Name:   "approval_0",
							Status: domain.ApprovalStatusApproved,
						},
						{
							Name:      "approval_1",
							Status:    domain.ApprovalStatusPending,
							Approvers: []string{"user@email.com"},
						},
					},
				},
				expectedResult: &domain.Appeal{
					ID:     validApprovalActionParam.AppealID,
					Status: domain.AppealStatusActive,
					Approvals: []*domain.Approval{
						{
							Name:   "approval_0",
							Status: domain.ApprovalStatusApproved,
						},
						{
							Name:      "approval_1",
							Status:    domain.ApprovalStatusApproved,
							Approvers: []string{"user@email.com"},
							Actor:     &user,
							UpdatedAt: timeNow,
						},
					},
				},
			},
			{
				name: "reject",
				expectedApprovalAction: domain.ApprovalAction{
					AppealID:     1,
					ApprovalName: "approval_1",
					Actor:        "user@email.com",
					Action:       "reject",
				},
				expectedAppealDetails: &domain.Appeal{
					ID:     validApprovalActionParam.AppealID,
					Status: domain.AppealStatusPending,
					Approvals: []*domain.Approval{
						{
							Name:   "approval_0",
							Status: domain.ApprovalStatusApproved,
						},
						{
							Name:      "approval_1",
							Status:    domain.ApprovalStatusPending,
							Approvers: []string{"user@email.com"},
						},
					},
				},
				expectedResult: &domain.Appeal{
					ID:     validApprovalActionParam.AppealID,
					Status: domain.AppealStatusRejected,
					Approvals: []*domain.Approval{
						{
							Name:   "approval_0",
							Status: domain.ApprovalStatusApproved,
						},
						{
							Name:      "approval_1",
							Status:    domain.ApprovalStatusRejected,
							Approvers: []string{"user@email.com"},
							Actor:     &user,
							UpdatedAt: timeNow,
						},
					},
				},
			},
			{
				name: "reject in the middle step",
				expectedApprovalAction: domain.ApprovalAction{
					AppealID:     1,
					ApprovalName: "approval_1",
					Actor:        user,
					Action:       "reject",
				},
				expectedAppealDetails: &domain.Appeal{
					ID:     validApprovalActionParam.AppealID,
					Status: domain.AppealStatusPending,
					Approvals: []*domain.Approval{
						{
							Name:   "approval_0",
							Status: domain.ApprovalStatusApproved,
						},
						{
							Name:      "approval_1",
							Status:    domain.ApprovalStatusPending,
							Approvers: []string{"user@email.com"},
						},
						{
							Name:   "approval_2",
							Status: domain.ApprovalStatusPending,
						},
					},
				},
				expectedResult: &domain.Appeal{
					ID:     validApprovalActionParam.AppealID,
					Status: domain.AppealStatusRejected,
					Approvals: []*domain.Approval{
						{
							Name:   "approval_0",
							Status: domain.ApprovalStatusApproved,
						},
						{
							Name:      "approval_1",
							Status:    domain.ApprovalStatusRejected,
							Approvers: []string{"user@email.com"},
							Actor:     &user,
							UpdatedAt: timeNow,
						},
						{
							Name:      "approval_2",
							Status:    domain.ApprovalStatusSkipped,
							UpdatedAt: timeNow,
						},
					},
				},
			},
		}
		for _, tc := range testCases {
			s.Run(tc.name, func() {
				s.mockRepository.On("GetByID", validApprovalActionParam.AppealID).
					Return(tc.expectedAppealDetails, nil).
					Once()
				s.mockProviderService.On("GrantAccess", tc.expectedAppealDetails).
					Return(nil).
					Once()
				s.mockRepository.On("Update", mock.Anything).
					Return(nil).
					Once()

				actualResult, actualError := s.service.MakeAction(tc.expectedApprovalAction)

				s.Equal(tc.expectedResult, actualResult)
				s.Nil(actualError)
			})
		}
	})
}

// func (s *ServiceTestSuite) TestCancel() {
// 	s.Run("should return error from")
// }

func (s *ServiceTestSuite) TestGetPendingApprovals() {
	s.Run("should return error if got error from repository", func() {
		expectedError := errors.New("repository error")
		s.mockApprovalService.On("GetPendingApprovals", mock.Anything).Return(nil, expectedError).Once()

		actualResult, actualError := s.service.GetPendingApprovals("user@email.com")

		s.Nil(actualResult)
		s.EqualError(actualError, expectedError.Error())
	})
}

func TestService(t *testing.T) {
	suite.Run(t, new(ServiceTestSuite))
}