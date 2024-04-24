package appeal_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/goto/guardian/core/appeal"
	appealmocks "github.com/goto/guardian/core/appeal/mocks"
	"github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/mocks"
	"github.com/goto/guardian/pkg/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

var (
	timeNow = time.Now()
)

type serviceTestHelper struct {
	mockRepository      *appealmocks.Repository
	mockApprovalService *appealmocks.ApprovalService
	mockResourceService *appealmocks.ResourceService
	mockProviderService *appealmocks.ProviderService
	mockPolicyService   *appealmocks.PolicyService
	mockGrantService    *appealmocks.GrantService
	mockIAMManager      *appealmocks.IamManager
	mockIAMClient       *mocks.IAMClient
	mockNotifier        *appealmocks.Notifier
	mockAuditLogger     *appealmocks.AuditLogger

	service    *appeal.Service
	now        time.Time
	ctxMatcher interface{}
}

func (h *serviceTestHelper) assertExpectations(t *testing.T) {
	t.Helper()
	h.mockRepository.AssertExpectations(t)
	h.mockApprovalService.AssertExpectations(t)
	h.mockResourceService.AssertExpectations(t)
	h.mockProviderService.AssertExpectations(t)
	h.mockPolicyService.AssertExpectations(t)
	h.mockGrantService.AssertExpectations(t)
	h.mockIAMManager.AssertExpectations(t)
	h.mockIAMClient.AssertExpectations(t)
	h.mockNotifier.AssertExpectations(t)
	h.mockAuditLogger.AssertExpectations(t)
}

func newServiceTestHelper() *serviceTestHelper {
	h := &serviceTestHelper{}
	h.mockRepository = new(appealmocks.Repository)
	h.mockApprovalService = new(appealmocks.ApprovalService)
	h.mockResourceService = new(appealmocks.ResourceService)
	h.mockProviderService = new(appealmocks.ProviderService)
	h.mockPolicyService = new(appealmocks.PolicyService)
	h.mockGrantService = new(appealmocks.GrantService)
	h.mockIAMManager = new(appealmocks.IamManager)
	h.mockIAMClient = new(mocks.IAMClient)
	h.mockNotifier = new(appealmocks.Notifier)
	h.mockAuditLogger = new(appealmocks.AuditLogger)
	h.now = time.Now()
	h.ctxMatcher = mock.MatchedBy(func(ctx context.Context) bool { return true })

	service := appeal.NewService(appeal.ServiceDeps{
		h.mockRepository,
		h.mockApprovalService,
		h.mockResourceService,
		h.mockProviderService,
		h.mockPolicyService,
		h.mockGrantService,
		h.mockIAMManager,
		h.mockNotifier,
		validator.New(),
		log.NewNoop(),
		h.mockAuditLogger,
	})
	service.TimeNow = func() time.Time {
		return h.now
	}

	h.service = service
	return h
}

type ServiceTestSuite struct {
	suite.Suite
}

func TestService(t *testing.T) {
	suite.Run(t, new(ServiceTestSuite))
}

func (s *ServiceTestSuite) TestGetByID() {
	s.Run("should return error if id is empty/0", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedError := appeal.ErrAppealIDEmptyParam

		actualResult, actualError := h.service.GetByID(context.Background(), "")

		s.Nil(actualResult)
		s.EqualError(actualError, expectedError.Error())
	})

	s.Run("should return error if got any from repository", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedError := errors.New("repository error")
		h.mockRepository.EXPECT().GetByID(h.ctxMatcher, mock.Anything).Return(nil, expectedError).Once()

		id := uuid.New().String()
		actualResult, actualError := h.service.GetByID(context.Background(), id)

		s.Nil(actualResult)
		s.EqualError(actualError, expectedError.Error())
	})

	s.Run("should return record on success", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedID := uuid.New().String()
		expectedResult := &domain.Appeal{
			ID: expectedID,
		}
		h.mockRepository.EXPECT().GetByID(h.ctxMatcher, expectedID).Return(expectedResult, nil).Once()

		actualResult, actualError := h.service.GetByID(context.Background(), expectedID)

		s.Equal(expectedResult, actualResult)
		s.Nil(actualError)
	})
}

func (s *ServiceTestSuite) TestFind() {
	s.Run("should return error if got any from repository", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedError := errors.New("unexpected repository error")
		h.mockRepository.EXPECT().Find(h.ctxMatcher, mock.Anything).Return(nil, expectedError).Once()

		actualResult, actualError := h.service.Find(context.Background(), &domain.ListAppealsFilter{})

		s.Nil(actualResult)
		s.EqualError(actualError, expectedError.Error())
	})

	s.Run("should return records on success", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedFilters := &domain.ListAppealsFilter{
			AccountID: "user@email.com",
		}
		expectedResult := []*domain.Appeal{
			{
				ID:         "1",
				ResourceID: "1",
				AccountID:  "user@email.com",
				Role:       "viewer",
			},
		}
		h.mockRepository.EXPECT().Find(h.ctxMatcher, expectedFilters).Return(expectedResult, nil).Once()

		actualResult, actualError := h.service.Find(context.Background(), expectedFilters)

		s.Equal(expectedResult, actualResult)
		s.Nil(actualError)
	})
}

func (s *ServiceTestSuite) TestCreate() {
	appeal.TimeNow = func() time.Time {
		return timeNow
	}
	accountID := "test@email.com"

	s.Run("should return error if got error from resource service", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedError := fmt.Errorf("error getting resource map: %w", errors.New("resource service error"))
		expectedProviders := []*domain.Provider{}
		expectedPolicies := []*domain.Policy{}
		expectedAppeals := []*domain.Appeal{}
		h.mockResourceService.EXPECT().Find(mock.Anything, mock.Anything).Return(nil, expectedError).Once()
		h.mockProviderService.EXPECT().Find(mock.Anything).Return(expectedProviders, nil).Once()
		h.mockPolicyService.EXPECT().Find(mock.Anything).Return(expectedPolicies, nil).Once()
		h.mockRepository.EXPECT().
			Find(h.ctxMatcher, mock.Anything).
			Return(expectedAppeals, nil).Once()

		actualError := h.service.Create(context.Background(), []*domain.Appeal{})

		s.ErrorIs(actualError, expectedError)
	})

	s.Run("should return error if got error from provider service", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedResources := []*domain.Resource{}
		expectedError := fmt.Errorf("error getting provider map: %w", errors.New("provider service error"))
		expectedPolicies := []*domain.Policy{}
		expectedAppeals := []*domain.Appeal{}
		h.mockResourceService.EXPECT().Find(mock.Anything, mock.Anything).Return(expectedResources, nil).Once()
		h.mockProviderService.EXPECT().Find(mock.Anything).Return(nil, expectedError).Once()
		h.mockPolicyService.EXPECT().Find(mock.Anything).Return(expectedPolicies, nil).Once()
		h.mockRepository.EXPECT().
			Find(h.ctxMatcher, mock.Anything).
			Return(expectedAppeals, nil).Once()

		actualError := h.service.Create(context.Background(), []*domain.Appeal{})

		s.ErrorIs(actualError, expectedError)
	})

	s.Run("should return error if got error from policy service", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedResources := []*domain.Resource{}
		expectedProviders := []*domain.Provider{}
		expectedError := fmt.Errorf("error getting service map: %w", errors.New("service service error"))
		expectedAppeals := []*domain.Appeal{}
		h.mockResourceService.EXPECT().Find(mock.Anything, mock.Anything).Return(expectedResources, nil).Once()
		h.mockProviderService.EXPECT().Find(mock.Anything).Return(expectedProviders, nil).Once()
		h.mockPolicyService.EXPECT().Find(mock.Anything).Return(nil, expectedError).Once()
		h.mockRepository.EXPECT().
			Find(h.ctxMatcher, mock.Anything).
			Return(expectedAppeals, nil).Once()

		actualError := h.service.Create(context.Background(), []*domain.Appeal{})

		s.ErrorIs(actualError, expectedError)
	})

	s.Run("should return error if got error from appeal repository", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedResources := []*domain.Resource{}
		expectedProviders := []*domain.Provider{}
		expectedPolicies := []*domain.Policy{}
		h.mockResourceService.EXPECT().Find(mock.Anything, mock.Anything).Return(expectedResources, nil).Once()
		h.mockProviderService.EXPECT().Find(mock.Anything).Return(expectedProviders, nil).Once()
		h.mockPolicyService.EXPECT().Find(mock.Anything).Return(expectedPolicies, nil).Once()
		expectedError := errors.New("appeal repository error")
		h.mockRepository.EXPECT().
			Find(h.ctxMatcher, mock.Anything).
			Return(nil, expectedError).Once()

		actualError := h.service.Create(context.Background(), []*domain.Appeal{})

		s.ErrorIs(actualError, expectedError)
	})

	s.Run("should return error for invalid appeals", func() {
		testProvider := &domain.Provider{
			ID:   "1",
			Type: "provider_type",
			URN:  "provider_urn",
			Config: &domain.ProviderConfig{
				Appeal: &domain.AppealConfig{
					AllowPermanentAccess: false,
				},
				Resources: []*domain.ResourceConfig{
					{
						Type: "resource_type",
						Policy: &domain.PolicyConfig{
							ID:      "policy_id",
							Version: 1,
						},
						Roles: []*domain.Role{
							{
								ID: "role_1",
							},
						},
					},
				},
			},
		}
		expDate := timeNow.Add(24 * time.Hour)

		testPolicies := []*domain.Policy{{ID: "policy_id", Version: 1}}

		testCases := []struct {
			name                          string
			resources                     []*domain.Resource
			providers                     []*domain.Provider
			policies                      []*domain.Policy
			existingAppeals               []*domain.Appeal
			activeGrants                  []domain.Grant
			callMockValidateAppeal        bool
			expectedAppealValidationError error
			callMockGetPermissions        bool
			appeals                       []*domain.Appeal
			expectedError                 error
		}{
			{
				name: "creating appeal for other normal user with allow_on_behalf=false",
				appeals: []*domain.Appeal{{
					CreatedBy:  "addOnBehalfApprovedNotification-user",
					AccountID:  "addOnBehalfApprovedNotification-user-2",
					ResourceID: "1",
					Role:       "addOnBehalfApprovedNotification-role",
				}},
				resources: []*domain.Resource{{
					ID:           "1",
					ProviderType: testProvider.Type,
					ProviderURN:  testProvider.URN,
					Type:         "resource_type",
				}},
				providers:              []*domain.Provider{testProvider},
				policies:               []*domain.Policy{{ID: "policy_id", Version: 1, AppealConfig: &domain.PolicyAppealConfig{AllowOnBehalf: false}}},
				callMockValidateAppeal: true,
				callMockGetPermissions: true,
				expectedError:          appeal.ErrCannotCreateAppealForOtherUser,
			},
			{
				name: "duplicate appeal",
				existingAppeals: []*domain.Appeal{{
					CreatedBy:  "test-user",
					AccountID:  "test-user",
					ResourceID: "1",
					Role:       "test-role",
					Status:     domain.AppealStatusPending,
				}},
				appeals: []*domain.Appeal{{
					CreatedBy:  "test-user",
					AccountID:  "test-user",
					ResourceID: "1",
					Role:       "test-role",
				}},
				expectedError: appeal.ErrAppealDuplicate,
			},
			{
				name: "resource not found",
				resources: []*domain.Resource{{
					ID: "1",
				}},
				appeals: []*domain.Appeal{{
					CreatedBy:  "test-user",
					AccountID:  "test-user",
					ResourceID: "2",
					Role:       "test-role",
				}},
				expectedError: appeal.ErrResourceNotFound,
			},
			{
				name: "provider type not found",
				resources: []*domain.Resource{{
					ID:           "1",
					ProviderType: "invalid_provider_type",
					ProviderURN:  "provider_urn",
				}},
				providers:     []*domain.Provider{testProvider},
				appeals:       []*domain.Appeal{{ResourceID: "1"}},
				expectedError: appeal.ErrProviderNotFound,
			},
			{
				name: "provider urn not found",
				resources: []*domain.Resource{{
					ID:           "1",
					ProviderType: "provider_type",
					ProviderURN:  "invalid_provider_urn",
				}},
				providers:     []*domain.Provider{testProvider},
				appeals:       []*domain.Appeal{{ResourceID: "1"}},
				expectedError: appeal.ErrProviderNotFound,
			},
			{
				name: "user still have active grant",
				resources: []*domain.Resource{{
					ID:           "1",
					Type:         "resource_type",
					ProviderType: testProvider.Type,
					ProviderURN:  testProvider.URN,
				}},
				activeGrants: []domain.Grant{{
					AccountID:  "test-user",
					ResourceID: "1",
					Role:       "test-role",
					Status:     domain.GrantStatusActive,
				}},
				policies: testPolicies,
				appeals: []*domain.Appeal{{
					CreatedBy:  "test-user",
					AccountID:  "test-user",
					ResourceID: "1",
					Role:       "test-role",
				}},
				providers:     []*domain.Provider{testProvider},
				expectedError: appeal.ErrAppealFoundActiveGrant,
			},
			{
				name: "invalid extension duration",
				resources: []*domain.Resource{{
					ID:           "1",
					Type:         "resource_type",
					ProviderType: testProvider.Type,
					ProviderURN:  testProvider.URN,
				}},
				activeGrants: []domain.Grant{{
					AccountID:  "test-user",
					ResourceID: "1",
					Role:       "test-role",
					Status:     domain.GrantStatusActive,
				}},
				appeals: []*domain.Appeal{{
					CreatedBy:  "test-user",
					AccountID:  "test-user",
					ResourceID: "1",
					Role:       "test-role",
				}},
				policies: testPolicies,
				providers: []*domain.Provider{{
					ID:   "1",
					Type: testProvider.Type,
					URN:  testProvider.URN,
					Config: &domain.ProviderConfig{
						Appeal: &domain.AppealConfig{
							AllowActiveAccessExtensionIn: "invalid",
						},
						Resources: testProvider.Config.Resources,
					},
				}},
				expectedError: appeal.ErrAppealInvalidExtensionDuration,
			},
			{
				name: "extension not eligible",
				resources: []*domain.Resource{{
					ID:           "1",
					Type:         "resource_type",
					ProviderType: testProvider.Type,
					ProviderURN:  testProvider.URN,
				}},
				activeGrants: []domain.Grant{{
					AccountID:      "test-user",
					ResourceID:     "1",
					Role:           "test-role",
					Status:         domain.GrantStatusActive,
					ExpirationDate: &expDate,
				}},
				appeals: []*domain.Appeal{{
					CreatedBy:  "test-user",
					AccountID:  "test-user",
					ResourceID: "1",
					Role:       "test-role",
				}},
				policies: testPolicies,
				providers: []*domain.Provider{{
					ID:   "1",
					Type: testProvider.Type,
					URN:  testProvider.URN,
					Config: &domain.ProviderConfig{
						Appeal: &domain.AppealConfig{
							AllowActiveAccessExtensionIn: "23h",
						},
						Resources: testProvider.Config.Resources,
					},
				}},
				expectedError: appeal.ErrGrantNotEligibleForExtension,
			},
			{
				name: "duration not found when the appeal config prevents permanent access",
				resources: []*domain.Resource{{
					ID:           "1",
					ProviderType: "provider_type",
					ProviderURN:  "provider_urn",
					Type:         "resource_type",
				}},
				policies:                      []*domain.Policy{{ID: "policy_id", Version: 1}},
				providers:                     []*domain.Provider{testProvider},
				callMockValidateAppeal:        true,
				expectedAppealValidationError: provider.ErrAppealValidationDurationNotSpecified,
				appeals: []*domain.Appeal{{
					ResourceID: "1",
				}},
				expectedError: provider.ErrAppealValidationDurationNotSpecified,
			},
			{
				name: "empty duration option",
				resources: []*domain.Resource{{
					ID:           "1",
					ProviderType: "provider_type",
					ProviderURN:  "provider_urn",
					Type:         "resource_type",
				}},
				policies:                      testPolicies,
				providers:                     []*domain.Provider{testProvider},
				callMockValidateAppeal:        true,
				expectedAppealValidationError: provider.ErrAppealValidationEmptyDuration,
				appeals: []*domain.Appeal{{
					ResourceID: "1",
					Options: &domain.AppealOptions{
						Duration: "",
					},
				}},
				expectedError: provider.ErrAppealValidationEmptyDuration,
			},
			{
				name: "invalid duration value",
				resources: []*domain.Resource{{
					ID:           "1",
					ProviderType: "provider_type",
					ProviderURN:  "provider_urn",
					Type:         "resource_type",
				}},
				policies:                      testPolicies,
				providers:                     []*domain.Provider{testProvider},
				callMockValidateAppeal:        true,
				expectedAppealValidationError: provider.ErrAppealValidationInvalidDurationValue,
				appeals: []*domain.Appeal{{
					ResourceID: "1",
					Options: &domain.AppealOptions{
						Duration: "invalid-duration",
					},
				}},
				expectedError: provider.ErrAppealValidationInvalidDurationValue,
			},
			{
				name: "invalid role",
				resources: []*domain.Resource{{
					ID:           "1",
					ProviderType: "provider_type",
					ProviderURN:  "provider_urn",
					Type:         "resource_type",
				}},
				policies:                      testPolicies,
				providers:                     []*domain.Provider{testProvider},
				callMockValidateAppeal:        true,
				expectedAppealValidationError: provider.ErrInvalidRole,
				appeals: []*domain.Appeal{{
					ResourceID: "1",
					Role:       "invalid_role",
					Options: &domain.AppealOptions{
						ExpirationDate: &timeNow,
					},
				}},
				expectedError: appeal.ErrInvalidRole,
			},
			{
				name: "resource type not found",
				resources: []*domain.Resource{{
					ID:           "1",
					ProviderType: "provider_type",
					ProviderURN:  "provider_urn",
					Type:         "invalid_resource_type",
				}},
				policies:      testPolicies,
				providers:     []*domain.Provider{testProvider},
				appeals:       []*domain.Appeal{{ResourceID: "1"}},
				expectedError: appeal.ErrInvalidResourceType,
			},
			{
				name: "policy id not found",
				resources: []*domain.Resource{{
					ID:           "1",
					ProviderType: "provider_type",
					ProviderURN:  "provider_urn",
					Type:         "resource_type",
				}},
				providers: []*domain.Provider{testProvider},
				appeals: []*domain.Appeal{{
					ResourceID: "1",
					Role:       "role_1",
					Options: &domain.AppealOptions{
						ExpirationDate: &timeNow,
					},
				}},
				expectedError: appeal.ErrPolicyNotFound,
			},
			{
				name: "policy version not found",
				resources: []*domain.Resource{{
					ID:           "1",
					ProviderType: "provider_type",
					ProviderURN:  "provider_urn",
					Type:         "resource_type",
				}},
				providers: []*domain.Provider{testProvider},
				policies: []*domain.Policy{{
					ID: "policy_id",
				}},
				appeals: []*domain.Appeal{{
					ResourceID: "1",
					Role:       "role_1",
					Options: &domain.AppealOptions{
						ExpirationDate: &timeNow,
					},
				}},
				expectedError: appeal.ErrPolicyNotFound,
			},
			{
				name: "appeal duration not found in policy appeal config",
				resources: []*domain.Resource{{
					ID:           "1",
					ProviderType: "provider_type",
					ProviderURN:  "provider_urn",
					Type:         "resource_type",
				}},
				providers: []*domain.Provider{testProvider},
				policies: []*domain.Policy{{
					ID:      "policy_id",
					Version: uint(1),
					AppealConfig: &domain.PolicyAppealConfig{
						DurationOptions: []domain.AppealDurationOption{
							{Name: "1 Day", Value: "24h"},
							{Name: "3 Days", Value: "72h"},
							{Name: "90 Days", Value: "2160h"},
						},
					},
				}},
				callMockValidateAppeal: true,
				callMockGetPermissions: true,
				appeals: []*domain.Appeal{{
					ResourceID:    "1",
					Role:          "role_1",
					PolicyID:      "policy_id",
					PolicyVersion: uint(1),
					Options: &domain.AppealOptions{
						Duration: "100h",
					},
				}},
				expectedError: appeal.ErrDurationNotAllowed,
			},
		}

		for _, tc := range testCases {
			s.Run(tc.name, func() {
				h := newServiceTestHelper()
				h.mockResourceService.EXPECT().
					Find(mock.Anything, mock.Anything).
					Return(tc.resources, nil).Once()
				h.mockProviderService.EXPECT().
					Find(mock.Anything).
					Return(tc.providers, nil).Once()
				h.mockPolicyService.EXPECT().
					Find(mock.Anything).
					Return(tc.policies, nil).Once()
				h.mockRepository.EXPECT().
					Find(h.ctxMatcher, mock.Anything).
					Return(tc.existingAppeals, nil).Once()
				h.mockGrantService.EXPECT().
					List(h.ctxMatcher, mock.AnythingOfType("domain.ListGrantsFilter")).
					Return(tc.activeGrants, nil)
				if tc.callMockValidateAppeal {
					h.mockProviderService.EXPECT().
						ValidateAppeal(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
						Return(tc.expectedAppealValidationError).Once()
				}
				if tc.callMockGetPermissions {
					h.mockProviderService.EXPECT().
						GetPermissions(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
						Return([]interface{}{}, nil).Once()
				}

				actualError := h.service.Create(context.Background(), tc.appeals)

				s.Contains(actualError.Error(), tc.expectedError.Error())
			})
		}
	})

	s.Run("should return error if got error from repository on bulk upsert", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedResources := []*domain.Resource{}
		expectedProviders := []*domain.Provider{}
		expectedPolicies := []*domain.Policy{}
		expectedPendingAppeals := []*domain.Appeal{}
		h.mockResourceService.EXPECT().
			Find(mock.Anything, mock.Anything).
			Return(expectedResources, nil).Once()
		h.mockProviderService.EXPECT().
			Find(mock.Anything).
			Return(expectedProviders, nil).Once()
		h.mockPolicyService.EXPECT().
			Find(mock.Anything).
			Return(expectedPolicies, nil).Once()
		h.mockRepository.EXPECT().
			Find(h.ctxMatcher, mock.Anything).
			Return(expectedPendingAppeals, nil).Once()
		h.mockRepository.EXPECT().
			BulkUpsert(h.ctxMatcher, mock.Anything).
			Return(assert.AnError).Once()

		actualError := h.service.Create(context.Background(), []*domain.Appeal{})

		s.ErrorIs(actualError, assert.AnError)
	})

	s.Run("should return appeals on success", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		resources := []*domain.Resource{
			{
				ID:           "1",
				Type:         "resource_type_1",
				ProviderType: "provider_type",
				ProviderURN:  "provider1",
				Details: map[string]interface{}{
					"owner": []string{"resource.owner@email.com"},
				},
			},
			{
				ID:           "2",
				Type:         "resource_type_2",
				ProviderType: "provider_type",
				ProviderURN:  "provider1",
				Details: map[string]interface{}{
					"owner": []string{"resource.owner@email.com"},
				},
			},
		}
		providers := []*domain.Provider{
			{
				ID:   "1",
				Type: "provider_type",
				URN:  "provider1",
				Config: &domain.ProviderConfig{
					Appeal: &domain.AppealConfig{
						AllowPermanentAccess:         true,
						AllowActiveAccessExtensionIn: "24h",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: "resource_type_1",
							Policy: &domain.PolicyConfig{
								ID:      "policy_1",
								Version: 1,
							},
							Roles: []*domain.Role{
								{
									ID:          "role_id",
									Permissions: []interface{}{"test-permission-1"},
								},
							},
						},
						{
							Type: "resource_type_2",
							Policy: &domain.PolicyConfig{
								ID:      "policy_2",
								Version: 1,
							},
							Roles: []*domain.Role{
								{
									ID:          "role_id",
									Permissions: []interface{}{"test-permission-1"},
								},
							},
						},
					},
				},
			},
		}
		expDate := timeNow.Add(23 * time.Hour)
		expectedExistingAppeals := []*domain.Appeal{}
		expectedActiveGrants := []domain.Grant{
			{
				ID:         "99",
				AccountID:  accountID,
				ResourceID: "2",
				Resource: &domain.Resource{
					ID:  "2",
					URN: "urn",
				},
				Role:           "role_id",
				Status:         domain.GrantStatusActive,
				ExpirationDate: &expDate,
			},
		}
		policies := []*domain.Policy{
			{
				ID:      "policy_1",
				Version: 1,
				Steps: []*domain.Step{
					{
						Name:     "step_1",
						Strategy: "manual",
						Approvers: []string{
							"$appeal.resource.details.owner",
						},
					},
					{
						Name:     "step_2",
						Strategy: "manual",
						Approvers: []string{
							"$appeal.creator.managers",
							"$appeal.creator.managers", // test duplicate approvers
						},
					},
				},
				IAM: &domain.IAMConfig{
					Provider: "http",
					Config: map[string]interface{}{
						"url": "http://localhost",
					},
					Schema: map[string]string{
						"managers": `managers`,
						"name":     "name",
						"role":     `$response.roles[0].name`,
						"roles":    `map($response.roles, {#.name})`,
					},
				},
				AppealConfig: &domain.PolicyAppealConfig{AllowOnBehalf: true},
			},
			{
				ID:      "policy_2",
				Version: 1,
				Steps: []*domain.Step{
					{
						Name:     "step_1",
						Strategy: "manual",
						Approvers: []string{
							"$appeal.resource.details.owner",
						},
					},
					{
						Name:     "step_2",
						Strategy: "manual",
						Approvers: []string{
							`$appeal.creator != nil ? $appeal.creator.managers : "approver@example.com"`,
						},
					},
				},
				IAM: &domain.IAMConfig{
					Provider: "http",
					Config: map[string]interface{}{
						"url": "http://localhost",
					},
					Schema: map[string]string{
						"managers": `managers`,
						"name":     "name",
						"role":     `$response.roles[0].name`,
						"roles":    `map($response.roles, {#.name})`,
					},
				},
				AppealConfig: &domain.PolicyAppealConfig{
					AllowOnBehalf:              true,
					AllowCreatorDetailsFailure: true,
				},
			},
		}
		expectedCreatorUser := map[string]interface{}{
			"managers": []interface{}{"user.approver@email.com"},
			"name":     "test-name",
			"role":     "test-role-1",
			"roles":    []interface{}{"test-role-1", "test-role-2"},
		}
		expectedAppealsInsertionParam := []*domain.Appeal{
			{
				ResourceID:    resources[0].ID,
				Resource:      resources[0],
				PolicyID:      "policy_1",
				PolicyVersion: 1,
				Status:        domain.AppealStatusPending,
				AccountID:     accountID,
				AccountType:   domain.DefaultAppealAccountType,
				CreatedBy:     accountID,
				Creator:       expectedCreatorUser,
				Role:          "role_id",
				Permissions:   []string{"test-permission-1"},
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
						Status:        domain.ApprovalStatusBlocked,
						PolicyID:      "policy_1",
						PolicyVersion: 1,
						Approvers:     []string{"user.approver@email.com"},
					},
				},
				Description: "The answer is 42",
			},
			{
				ResourceID:    resources[1].ID,
				Resource:      resources[1],
				PolicyID:      "policy_2",
				PolicyVersion: 1,
				Status:        domain.AppealStatusPending,
				AccountID:     "addOnBehalfApprovedNotification-user",
				AccountType:   domain.DefaultAppealAccountType,
				CreatedBy:     accountID,
				Creator:       nil,
				Role:          "role_id",
				Permissions:   []string{"test-permission-1"},
				Approvals: []*domain.Approval{
					{
						Name:          "step_1",
						Index:         0,
						Status:        domain.ApprovalStatusPending,
						PolicyID:      "policy_2",
						PolicyVersion: 1,
						Approvers:     []string{"resource.owner@email.com"},
					},
					{
						Name:          "step_2",
						Index:         1,
						Status:        domain.ApprovalStatusBlocked,
						PolicyID:      "policy_2",
						PolicyVersion: 1,
						Approvers:     []string{"approver@example.com"},
					},
				},
				Description: "The answer is 42",
			},
		}
		expectedResult := []*domain.Appeal{
			{
				ID:            "1",
				ResourceID:    "1",
				Resource:      resources[0],
				PolicyID:      "policy_1",
				PolicyVersion: 1,
				Status:        domain.AppealStatusPending,
				AccountID:     accountID,
				AccountType:   domain.DefaultAppealAccountType,
				CreatedBy:     accountID,
				Creator:       expectedCreatorUser,
				Role:          "role_id",
				Permissions:   []string{"test-permission-1"},
				Approvals: []*domain.Approval{
					{
						ID:            "1",
						Name:          "step_1",
						Index:         0,
						Status:        domain.ApprovalStatusPending,
						PolicyID:      "policy_1",
						PolicyVersion: 1,
						Approvers:     []string{"resource.owner@email.com"},
					},
					{
						ID:            "2",
						Name:          "step_2",
						Index:         1,
						Status:        domain.ApprovalStatusBlocked,
						PolicyID:      "policy_1",
						PolicyVersion: 1,
						Approvers:     []string{"user.approver@email.com"},
					},
				},
				Description: "The answer is 42",
			},
			{
				ID:            "2",
				ResourceID:    "2",
				Resource:      resources[1],
				PolicyID:      "policy_2",
				PolicyVersion: 1,
				Status:        domain.AppealStatusPending,
				AccountID:     "addOnBehalfApprovedNotification-user",
				AccountType:   domain.DefaultAppealAccountType,
				CreatedBy:     accountID,
				Creator:       nil,
				Role:          "role_id",
				Permissions:   []string{"test-permission-1"},
				Approvals: []*domain.Approval{
					{
						ID:            "1",
						Name:          "step_1",
						Index:         0,
						Status:        domain.ApprovalStatusPending,
						PolicyID:      "policy_2",
						PolicyVersion: 1,
						Approvers:     []string{"resource.owner@email.com"},
					},
					{
						ID:            "2",
						Name:          "step_2",
						Index:         1,
						Status:        domain.ApprovalStatusBlocked,
						PolicyID:      "policy_2",
						PolicyVersion: 1,
						Approvers:     []string{"approver@example.com"},
					},
				},
				Description: "The answer is 42",
			},
		}

		appeals := []*domain.Appeal{
			{
				CreatedBy:  accountID,
				AccountID:  accountID,
				ResourceID: "1",
				Resource: &domain.Resource{
					ID:  "1",
					URN: "urn",
				},
				Role:        "role_id",
				Description: "The answer is 42",
			},
			{
				CreatedBy:  accountID,
				AccountID:  "addOnBehalfApprovedNotification-user",
				ResourceID: "2",
				Resource: &domain.Resource{
					ID:  "2",
					URN: "urn",
				},
				Role:        "role_id",
				Description: "The answer is 42",
			},
		}

		expectedResourceFilters := domain.ListResourcesFilter{IDs: []string{resources[0].ID, resources[1].ID}}
		h.mockResourceService.EXPECT().
			Find(mock.Anything, expectedResourceFilters).Return(resources, nil).Once()
		h.mockProviderService.EXPECT().
			Find(mock.Anything).Return(providers, nil).Once()
		h.mockPolicyService.EXPECT().
			Find(mock.Anything).Return(policies, nil).Once()
		expectedExistingAppealsFilters := &domain.ListAppealsFilter{
			Statuses:   []string{domain.AppealStatusPending},
			AccountIDs: []string{"test@email.com", "addOnBehalfApprovedNotification-user"},
		}
		h.mockRepository.EXPECT().
			Find(h.ctxMatcher, expectedExistingAppealsFilters).
			Return(expectedExistingAppeals, nil).Once()
		for _, a := range appeals {
			h.mockGrantService.EXPECT().
				List(h.ctxMatcher, domain.ListGrantsFilter{
					Statuses:    []string{string(domain.GrantStatusActive)},
					AccountIDs:  []string{a.AccountID},
					ResourceIDs: []string{a.ResourceID},
					Roles:       []string{a.Role},
					OrderBy:     []string{"updated_at:desc"},
				}).
				Return(expectedActiveGrants, nil).Once()
		}
		h.mockProviderService.EXPECT().
			ValidateAppeal(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
		h.mockProviderService.EXPECT().
			GetPermissions(mock.Anything, mock.Anything, mock.AnythingOfType("string"), "role_id").
			Return([]interface{}{"test-permission-1"}, nil)
		h.mockIAMManager.EXPECT().
			ParseConfig(mock.Anything).Return(nil, nil)
		h.mockIAMManager.EXPECT().
			GetClient(mock.Anything).Return(h.mockIAMClient, nil)
		expectedCreatorResponse := map[string]interface{}{
			"managers": []interface{}{"user.approver@email.com"},
			"name":     "test-name",
			"roles": []map[string]interface{}{
				{"name": "test-role-1"},
				{"name": "test-role-2"},
			},
		}
		h.mockIAMClient.EXPECT().
			GetUser(accountID).Return(expectedCreatorResponse, nil).Once()
		h.mockIAMClient.EXPECT().
			GetUser(accountID).Return(nil, errors.New("404 not found")).Once()
		h.mockRepository.EXPECT().
			BulkUpsert(h.ctxMatcher, expectedAppealsInsertionParam).
			Return(nil).
			Run(func(_a0 context.Context, appeals []*domain.Appeal) {
				for i, a := range appeals {
					a.ID = expectedResult[i].ID
					for j, approval := range a.Approvals {
						approval.ID = expectedResult[i].Approvals[j].ID
					}
				}
			}).
			Once()
		h.mockNotifier.EXPECT().
			Notify(h.ctxMatcher, mock.Anything).Return(nil).Once()
		h.mockAuditLogger.EXPECT().
			Log(mock.Anything, appeal.AuditKeyBulkInsert, mock.Anything).Return(nil).Once()

		actualError := h.service.Create(context.Background(), appeals)

		s.Nil(actualError)
		s.Equal(expectedResult, appeals)
	})

	s.Run("should return appeals on success with latest policy", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expDate := timeNow.Add(23 * time.Hour)

		resources := []*domain.Resource{
			{
				ID:           "1",
				Type:         "resource_type_1",
				ProviderType: "provider_type",
				ProviderURN:  "provider1",
				Details: map[string]interface{}{
					"owner": []string{"resource.owner@email.com"},
				},
			},
			{
				ID:           "2",
				Type:         "resource_type_2",
				ProviderType: "provider_type",
				ProviderURN:  "provider1",
				Details: map[string]interface{}{
					"owner": []string{"resource.owner@email.com"},
				},
			},
		}
		providers := []*domain.Provider{
			{
				ID:   "1",
				Type: "provider_type",
				URN:  "provider1",
				Config: &domain.ProviderConfig{
					Appeal: &domain.AppealConfig{
						AllowPermanentAccess:         true,
						AllowActiveAccessExtensionIn: "24h",
					},
					Resources: []*domain.ResourceConfig{
						{
							Type: "resource_type_1",
							Policy: &domain.PolicyConfig{ // specify policy with version
								ID:      "policy_1",
								Version: 1,
							},
							Roles: []*domain.Role{
								{
									ID:          "role_id",
									Permissions: []interface{}{"test-permission-1"},
								},
							},
						},
						{
							Type: "resource_type_2",
							Policy: &domain.PolicyConfig{ // specify policy without version (always use latest)
								ID: "policy_2",
							},
							Roles: []*domain.Role{
								{
									ID:          "role_id",
									Permissions: []interface{}{"test-permission-1"},
								},
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
						Name:     "step_1",
						Strategy: "manual",
						Approvers: []string{
							"$appeal.resource.details.owner",
						},
					},
					{
						Name:     "step_2",
						Strategy: "manual",
						Approvers: []string{
							`$appeal.creator != nil ? $appeal.creator.managers : "approver@example.com"`,
						},
					},
				},
				IAM: &domain.IAMConfig{
					Provider: "http",
					Config: map[string]interface{}{
						"url": "http://localhost",
					},
					Schema: map[string]string{
						"managers": `managers`,
						"name":     "name",
						"role":     `$response.roles[0].name`,
						"roles":    `map($response.roles, {#.name})`,
					},
				},
				AppealConfig: &domain.PolicyAppealConfig{
					AllowOnBehalf:              true,
					AllowCreatorDetailsFailure: true,
				},
			},
			{
				ID:      "policy_1",
				Version: 2,
				Steps: []*domain.Step{
					{
						Name:     "step_1",
						Strategy: "manual",
						Approvers: []string{
							"$appeal.resource.details.owner",
						},
					},
					{
						Name:     "step_2",
						Strategy: "manual",
						Approvers: []string{
							`$appeal.creator != nil ? $appeal.creator.managers : "approver@example.com"`,
						},
					},
				},
				IAM: &domain.IAMConfig{
					Provider: "http",
					Config: map[string]interface{}{
						"url": "http://localhost",
					},
					Schema: map[string]string{
						"managers": `managers`,
						"name":     "name",
						"role":     `$response.roles[0].name`,
						"roles":    `map($response.roles, {#.name})`,
					},
				},
				AppealConfig: &domain.PolicyAppealConfig{
					AllowOnBehalf:              true,
					AllowCreatorDetailsFailure: true,
				},
			},
			{
				ID:      "policy_2",
				Version: 1,
				Steps: []*domain.Step{
					{
						Name:     "step_1",
						Strategy: "manual",
						Approvers: []string{
							"$appeal.resource.details.owner",
						},
					},
					{
						Name:     "step_2",
						Strategy: "manual",
						Approvers: []string{
							"$appeal.creator.managers",
						},
					},
				},
				IAM: &domain.IAMConfig{
					Provider: "http",
					Config: map[string]interface{}{
						"url": "http://localhost",
					},
					Schema: map[string]string{
						"managers": `managers`,
						"name":     "name",
						"role":     `$response.roles[0].name`,
						"roles":    `map($response.roles, {#.name})`,
					},
				},
				AppealConfig: &domain.PolicyAppealConfig{
					AllowOnBehalf: true,
				},
			}, {
				ID:      "policy_2",
				Version: 20,
				Steps: []*domain.Step{
					{
						Name:     "step_1",
						Strategy: "manual",
						Approvers: []string{
							"$appeal.resource.details.owner",
						},
					},
					{
						Name:     "step_2",
						Strategy: "manual",
						Approvers: []string{
							"$appeal.creator.managers",
						},
					},
				},
				IAM: &domain.IAMConfig{
					Provider: "http",
					Config: map[string]interface{}{
						"url": "http://localhost",
					},
					Schema: map[string]string{
						"managers": `managers`,
						"name":     "name",
						"role":     `$response.roles[0].name`,
						"roles":    `map($response.roles, {#.name})`,
					},
				},
				AppealConfig: &domain.PolicyAppealConfig{
					AllowOnBehalf: true,
				},
			},
		}

		expectedCreatorUser := map[string]interface{}{
			"managers": []interface{}{"user.approver@email.com"},
			"name":     "test-name",
			"role":     "test-role-1",
			"roles":    []interface{}{"test-role-1", "test-role-2"},
		}
		expectedAppealsInsertionParam := []*domain.Appeal{
			{
				ResourceID:    resources[0].ID,
				Resource:      resources[0],
				PolicyID:      "policy_1",
				PolicyVersion: 1,
				Status:        domain.AppealStatusPending,
				AccountID:     "addOnBehalfApprovedNotification-user",
				AccountType:   domain.DefaultAppealAccountType,
				CreatedBy:     accountID,
				Creator:       nil,
				Role:          "role_id",
				Permissions:   []string{"test-permission-1"},
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
						Status:        domain.ApprovalStatusBlocked,
						PolicyID:      "policy_1",
						PolicyVersion: 1,
						Approvers:     []string{"approver@example.com"},
					},
				},
				Description: "The answer is 42",
			},
			{
				ResourceID:    resources[1].ID,
				Resource:      resources[1],
				PolicyID:      "policy_2",
				PolicyVersion: 20,
				Status:        domain.AppealStatusPending,
				AccountID:     accountID,
				AccountType:   domain.DefaultAppealAccountType,
				CreatedBy:     accountID,
				Creator:       expectedCreatorUser,
				Role:          "role_id",
				Permissions:   []string{"test-permission-1"},
				Approvals: []*domain.Approval{
					{
						Name:          "step_1",
						Index:         0,
						Status:        domain.ApprovalStatusPending,
						PolicyID:      "policy_2",
						PolicyVersion: 20,
						Approvers:     []string{"resource.owner@email.com"},
					},
					{
						Name:          "step_2",
						Index:         1,
						Status:        domain.ApprovalStatusBlocked,
						PolicyID:      "policy_2",
						PolicyVersion: 20,
						Approvers:     []string{"user.approver@email.com"},
					},
				},
				Description: "The answer is 42",
			},
		}
		expectedExistingAppeals := []*domain.Appeal{}
		expectedActiveGrants := []domain.Grant{
			{
				ID:         "99",
				AccountID:  accountID,
				ResourceID: "1",
				Resource: &domain.Resource{
					ID:  "1",
					URN: "urn",
				},
				Role:           "role_id",
				Status:         domain.GrantStatusActive,
				ExpirationDate: &expDate,
			},
		}
		expectedResult := []*domain.Appeal{
			{
				ID:            "1",
				ResourceID:    "1",
				Resource:      resources[0],
				PolicyID:      "policy_1",
				PolicyVersion: 1,
				Status:        domain.AppealStatusPending,
				AccountID:     "addOnBehalfApprovedNotification-user",
				AccountType:   domain.DefaultAppealAccountType,
				CreatedBy:     accountID,
				Creator:       nil,
				Role:          "role_id",
				Permissions:   []string{"test-permission-1"},
				Approvals: []*domain.Approval{
					{
						ID:            "1",
						Name:          "step_1",
						Index:         0,
						Status:        domain.ApprovalStatusPending,
						PolicyID:      "policy_1",
						PolicyVersion: 1,
						Approvers:     []string{"resource.owner@email.com"},
					},
					{
						ID:            "2",
						Name:          "step_2",
						Index:         1,
						Status:        domain.ApprovalStatusBlocked,
						PolicyID:      "policy_1",
						PolicyVersion: 1,
						Approvers:     []string{"approver@example.com"},
					},
				},
				Description: "The answer is 42",
			},
			{
				ID:            "2",
				ResourceID:    "2",
				Resource:      resources[1],
				PolicyID:      "policy_2",
				PolicyVersion: 20, // result expected to be created with the latest policy
				Status:        domain.AppealStatusPending,
				AccountID:     accountID,
				AccountType:   domain.DefaultAppealAccountType,
				CreatedBy:     accountID,
				Creator:       expectedCreatorUser,
				Role:          "role_id",
				Permissions:   []string{"test-permission-1"},
				Approvals: []*domain.Approval{
					{
						ID:            "1",
						Name:          "step_1",
						Index:         0,
						Status:        domain.ApprovalStatusPending,
						PolicyID:      "policy_2",
						PolicyVersion: 20,
						Approvers:     []string{"resource.owner@email.com"},
					},
					{
						ID:            "2",
						Name:          "step_2",
						Index:         1,
						Status:        domain.ApprovalStatusBlocked,
						PolicyID:      "policy_2",
						PolicyVersion: 20,
						Approvers:     []string{"user.approver@email.com"},
					},
				},
				Description: "The answer is 42",
			},
		}
		expectedResourceFilters := domain.ListResourcesFilter{IDs: []string{resources[0].ID, resources[1].ID}}
		expectedExistingAppealsFilters := &domain.ListAppealsFilter{
			Statuses:   []string{domain.AppealStatusPending},
			AccountIDs: []string{"addOnBehalfApprovedNotification-user", "test@email.com"},
		}

		appeals := []*domain.Appeal{
			{
				CreatedBy:  accountID,
				AccountID:  "addOnBehalfApprovedNotification-user",
				ResourceID: "1",
				Resource: &domain.Resource{
					ID:  "1",
					URN: "urn",
				},
				Role:        "role_id",
				Description: "The answer is 42",
			},
			{
				CreatedBy:  accountID,
				AccountID:  accountID,
				ResourceID: "2",
				Resource: &domain.Resource{
					ID:  "2",
					URN: "urn",
				},
				Role:        "role_id",
				Description: "The answer is 42",
			},
		}

		h.mockResourceService.EXPECT().
			Find(mock.Anything, expectedResourceFilters).Return(resources, nil).Once()
		h.mockProviderService.EXPECT().
			Find(mock.Anything).Return(providers, nil).Once()
		h.mockPolicyService.EXPECT().
			Find(mock.Anything).Return(policies, nil).Once()
		h.mockRepository.EXPECT().
			Find(h.ctxMatcher, expectedExistingAppealsFilters).
			Return(expectedExistingAppeals, nil).Once()
		for _, a := range appeals {
			h.mockGrantService.EXPECT().
				List(h.ctxMatcher, domain.ListGrantsFilter{
					Statuses:    []string{string(domain.GrantStatusActive)},
					AccountIDs:  []string{a.AccountID},
					ResourceIDs: []string{a.ResourceID},
					Roles:       []string{a.Role},
					OrderBy:     []string{"updated_at:desc"},
				}).
				Return(expectedActiveGrants, nil).Once()
		}
		h.mockProviderService.EXPECT().
			ValidateAppeal(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
		h.mockProviderService.EXPECT().
			GetPermissions(mock.Anything, mock.Anything, mock.AnythingOfType("string"), "role_id").
			Return([]interface{}{"test-permission-1"}, nil)
		h.mockIAMManager.EXPECT().
			ParseConfig(mock.Anything).Return(nil, nil)
		h.mockIAMManager.EXPECT().
			GetClient(mock.Anything).Return(h.mockIAMClient, nil)
		expectedCreatorResponse := map[string]interface{}{
			"managers": []interface{}{"user.approver@email.com"},
			"name":     "test-name",
			"roles": []map[string]interface{}{
				{"name": "test-role-1"},
				{"name": "test-role-2"},
			},
		}
		h.mockIAMClient.EXPECT().
			GetUser(accountID).Return(nil, errors.New("404 not found")).Once()
		h.mockIAMClient.EXPECT().
			GetUser(accountID).Return(expectedCreatorResponse, nil).Once()
		h.mockRepository.EXPECT().
			BulkUpsert(h.ctxMatcher, expectedAppealsInsertionParam).
			Return(nil).
			Run(func(_a0 context.Context, appeals []*domain.Appeal) {
				for i, a := range appeals {
					a.ID = expectedResult[i].ID
					for j, approval := range a.Approvals {
						approval.ID = expectedResult[i].Approvals[j].ID
					}
				}
			}).
			Once()
		h.mockNotifier.EXPECT().
			Notify(h.ctxMatcher, mock.Anything).Return(nil).Once()
		h.mockAuditLogger.EXPECT().
			Log(mock.Anything, appeal.AuditKeyBulkInsert, mock.Anything).
			Return(nil).Once()

		actualError := h.service.Create(context.Background(), appeals)

		s.Nil(actualError)
		s.Equal(expectedResult, appeals)
	})

	s.Run("additional appeal creation", func() {
		s.Run("should use the overridding policy", func() {
			h := newServiceTestHelper()
			defer h.assertExpectations(s.T())
			input := &domain.Appeal{
				ResourceID:    uuid.New().String(),
				AccountID:     "user@example.com",
				AccountType:   domain.DefaultAppealAccountType,
				CreatedBy:     "user@example.com",
				Role:          "test-role",
				PolicyID:      "test-policy",
				PolicyVersion: 99,
			}
			dummyResource := &domain.Resource{
				ID:           input.ResourceID,
				ProviderType: "test-provider-type",
				ProviderURN:  "test-provider-urn",
				Type:         "test-type",
				URN:          "test-urn",
			}
			expectedPermissions := []string{
				"test-permission-1",
				"test-permission-2",
			}
			dummyProvider := &domain.Provider{
				Type: dummyResource.ProviderType,
				URN:  dummyResource.ProviderURN,
				Config: &domain.ProviderConfig{
					Type: dummyResource.ProviderType,
					URN:  dummyResource.ProviderURN,
					Resources: []*domain.ResourceConfig{
						{
							Type: dummyResource.Type,
							Policy: &domain.PolicyConfig{
								ID:      "test-dummy-policy",
								Version: 1,
							},
							Roles: []*domain.Role{
								{
									ID: input.Role,
									Permissions: []interface{}{
										expectedPermissions[0],
										expectedPermissions[1],
									},
								},
							},
						},
					},
				},
			}
			dummyPolicy := &domain.Policy{
				ID:      "test-dummy-policy",
				Version: 1,
			}
			overriddingPolicy := &domain.Policy{
				ID:      input.PolicyID,
				Version: input.PolicyVersion,
				Steps: []*domain.Step{
					{
						Name:      "test-approval",
						Strategy:  "auto",
						ApproveIf: "true",
					},
				},
			}

			h.mockResourceService.EXPECT().Find(mock.Anything, mock.Anything).Return([]*domain.Resource{dummyResource}, nil).Once()
			h.mockProviderService.EXPECT().Find(mock.Anything).Return([]*domain.Provider{dummyProvider}, nil).Once()
			h.mockPolicyService.EXPECT().Find(mock.Anything).Return([]*domain.Policy{dummyPolicy, overriddingPolicy}, nil).Once()
			h.mockRepository.EXPECT().
				Find(h.ctxMatcher, mock.Anything).
				Return([]*domain.Appeal{}, nil).Once()
			h.mockGrantService.EXPECT().
				List(h.ctxMatcher, mock.AnythingOfType("domain.ListGrantsFilter")).
				Return([]domain.Grant{}, nil).Once()
			h.mockProviderService.EXPECT().ValidateAppeal(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
			h.mockProviderService.EXPECT().GetPermissions(mock.Anything, dummyProvider.Config, dummyResource.Type, input.Role).
				Return(dummyProvider.Config.Resources[0].Roles[0].Permissions, nil)
			h.mockRepository.EXPECT().
				BulkUpsert(h.ctxMatcher, mock.Anything).
				Return(nil).Once()
			h.mockNotifier.EXPECT().Notify(h.ctxMatcher, mock.Anything).Return(nil).Once()
			h.mockAuditLogger.EXPECT().Log(mock.Anything, appeal.AuditKeyBulkInsert, mock.Anything).Return(nil).Once()
			h.mockProviderService.EXPECT().
				IsExclusiveRoleAssignment(mock.Anything, mock.Anything, mock.Anything).
				Return(false).Once()
			h.mockGrantService.EXPECT().List(mock.Anything, mock.Anything).Return([]domain.Grant{}, nil).Once()
			h.mockGrantService.EXPECT().Prepare(mock.Anything, mock.Anything).Return(&domain.Grant{}, nil).Once()
			h.mockPolicyService.EXPECT().GetOne(mock.Anything, mock.Anything, mock.Anything).Return(overriddingPolicy, nil).Once()
			h.mockProviderService.EXPECT().GrantAccess(mock.Anything, mock.Anything).Return(nil).Once()

			err := h.service.Create(context.Background(), []*domain.Appeal{input}, appeal.CreateWithAdditionalAppeal())

			s.NoError(err)
			s.Equal("test-approval", input.Approvals[0].Name)
			s.Equal(expectedPermissions, input.Permissions)
		})
	})
}

func (s *ServiceTestSuite) TestCreateAppeal__WithExistingAppealAndWithAutoApprovalSteps() {
	h := newServiceTestHelper()
	defer h.assertExpectations(s.T())

	appeal.TimeNow = func() time.Time {
		return timeNow
	}

	accountID := "test@email.com"
	resourceIDs := []string{"1"}
	resources := []*domain.Resource{
		{
			ID:           "1",
			Type:         "resource_type_1",
			ProviderType: "provider_type",
			ProviderURN:  "provider1",
			Details: map[string]interface{}{
				"owner": []string{"resource.owner@email.com"},
			},
		},
	}

	providers := []*domain.Provider{
		{
			ID:   "1",
			Type: "provider_type",
			URN:  "provider1",
			Config: &domain.ProviderConfig{
				Appeal: &domain.AppealConfig{
					AllowPermanentAccess:         true,
					AllowActiveAccessExtensionIn: "24h",
				},
				Resources: []*domain.ResourceConfig{
					{
						Type: "resource_type_1",
						Policy: &domain.PolicyConfig{
							ID:      "policy_1",
							Version: 1,
						},
						Roles: []*domain.Role{
							{
								ID:          "role_id",
								Permissions: []interface{}{"test-permission"},
							},
						},
					},
				},
			},
		},
	}

	expectedExistingAppeals := []*domain.Appeal{}
	currentActiveGrant := domain.Grant{
		ID:         "99",
		AccountID:  accountID,
		ResourceID: "1",
		Resource: &domain.Resource{
			ID:  "1",
			URN: "urn",
		},
		Role:   "role_id",
		Status: domain.AppealStatusApproved,
	}
	expectedExistingGrants := []domain.Grant{currentActiveGrant}

	policies := []*domain.Policy{
		{
			ID:      "policy_1",
			Version: 1,
			Steps: []*domain.Step{
				{
					Name:        "step_1",
					Strategy:    "auto",
					AllowFailed: false,
					ApproveIf:   "1==1",
				},
				{
					Name:        "step_2",
					Strategy:    "manual",
					When:        "1==0",
					AllowFailed: false,
					Approvers:   []string{"test-approver@email.com"},
				},
			},
			IAM: &domain.IAMConfig{
				Provider: "http",
				Config: map[string]interface{}{
					"url": "http://localhost",
				},
			},
		},
	}

	expectedCreatorUser := map[string]interface{}{
		"managers": []interface{}{"user.approver@email.com"},
	}
	expectedAppealsInsertionParam := []*domain.Appeal{
		{
			ResourceID:    resources[0].ID,
			Resource:      resources[0],
			PolicyID:      "policy_1",
			PolicyVersion: 1,
			Status:        domain.AppealStatusApproved,
			AccountID:     accountID,
			AccountType:   domain.DefaultAppealAccountType,
			CreatedBy:     accountID,
			Creator:       expectedCreatorUser,
			Role:          "role_id",
			Permissions:   []string{"test-permission"},
			Approvals: []*domain.Approval{
				{
					Name:          "step_1",
					Index:         0,
					Status:        domain.ApprovalStatusApproved,
					PolicyID:      "policy_1",
					PolicyVersion: 1,
				}, {
					Name:          "step_2",
					Index:         1,
					Status:        domain.ApprovalStatusSkipped,
					PolicyID:      "policy_1",
					PolicyVersion: 1,
					Approvers:     []string{"test-approver@email.com"},
				},
			},
			Grant: &domain.Grant{
				ResourceID:  resources[0].ID,
				Status:      domain.GrantStatusActive,
				AccountID:   accountID,
				AccountType: domain.DefaultAppealAccountType,
				Role:        "role_id",
				Permissions: []string{"test-permission"},
				Resource:    resources[0],
			},
		},
	}

	expectedResult := []*domain.Appeal{
		{
			ID:            "1",
			ResourceID:    "1",
			Resource:      resources[0],
			PolicyID:      "policy_1",
			PolicyVersion: 1,
			Status:        domain.AppealStatusApproved,
			AccountID:     accountID,
			AccountType:   domain.DefaultAppealAccountType,
			CreatedBy:     accountID,
			Creator:       expectedCreatorUser,
			Role:          "role_id",
			Permissions:   []string{"test-permission"},
			Approvals: []*domain.Approval{
				{
					ID:            "1",
					Name:          "step_1",
					Index:         0,
					Status:        domain.ApprovalStatusApproved,
					PolicyID:      "policy_1",
					PolicyVersion: 1,
				},
				{
					ID:            "2",
					Name:          "step_2",
					Index:         1,
					Status:        domain.ApprovalStatusSkipped,
					PolicyID:      "policy_1",
					PolicyVersion: 1,
					Approvers:     []string{"test-approver@email.com"},
				},
			},
			Grant: &domain.Grant{
				ResourceID:  "1",
				Status:      domain.GrantStatusActive,
				AccountID:   accountID,
				AccountType: domain.DefaultAppealAccountType,
				Role:        "role_id",
				Permissions: []string{"test-permission"},
				Resource:    resources[0],
			},
		},
	}

	appeals := []*domain.Appeal{
		{
			CreatedBy:  accountID,
			AccountID:  accountID,
			ResourceID: "1",
			Resource: &domain.Resource{
				ID:  "1",
				URN: "urn",
			},
			Role: "role_id",
		},
	}

	expectedResourceFilters := domain.ListResourcesFilter{IDs: resourceIDs}
	h.mockResourceService.EXPECT().Find(mock.Anything, expectedResourceFilters).Return(resources, nil).Once()
	h.mockProviderService.EXPECT().Find(mock.Anything).Return(providers, nil).Once()
	h.mockPolicyService.EXPECT().Find(mock.Anything).Return(policies, nil).Once()
	expectedExistingAppealsFilters := &domain.ListAppealsFilter{
		Statuses:   []string{domain.AppealStatusPending},
		AccountIDs: []string{accountID},
	}
	h.mockRepository.EXPECT().
		Find(h.ctxMatcher, expectedExistingAppealsFilters).
		Return(expectedExistingAppeals, nil).Once()
	h.mockGrantService.EXPECT().
		List(h.ctxMatcher, domain.ListGrantsFilter{
			Statuses:    []string{string(domain.GrantStatusActive)},
			AccountIDs:  []string{appeals[0].AccountID},
			ResourceIDs: []string{appeals[0].ResourceID},
			Roles:       []string{appeals[0].Role},
			OrderBy:     []string{"updated_at:desc"},
		}).
		Return(expectedExistingGrants, nil).Once()
	// duplicate call with slight change in filters but the code needs it in order to work. appeal create code needs to be refactored.
	h.mockProviderService.EXPECT().
		IsExclusiveRoleAssignment(h.ctxMatcher, mock.Anything, mock.Anything).
		Return(false).Once()
	h.mockGrantService.EXPECT().
		List(h.ctxMatcher, domain.ListGrantsFilter{
			Statuses:    []string{string(domain.GrantStatusActive)},
			AccountIDs:  []string{appeals[0].AccountID},
			ResourceIDs: []string{appeals[0].ResourceID},
			Permissions: []string{"test-permission"},
		}).
		Return(expectedExistingGrants, nil).Once()
	h.mockProviderService.EXPECT().ValidateAppeal(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	h.mockProviderService.EXPECT().GetPermissions(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return([]interface{}{"test-permission"}, nil)
	h.mockIAMManager.EXPECT().ParseConfig(mock.Anything).Return(nil, nil)
	h.mockIAMManager.EXPECT().GetClient(mock.Anything).Return(h.mockIAMClient, nil)
	h.mockIAMClient.EXPECT().GetUser(accountID).Return(expectedCreatorUser, nil)

	preparedGrant := &domain.Grant{
		Status:      domain.GrantStatusActive,
		AccountID:   accountID,
		AccountType: domain.DefaultAppealAccountType,
		ResourceID:  "1",
		Role:        "role_id",
		Permissions: []string{"test-permission"},
	}
	h.mockGrantService.EXPECT().
		Prepare(h.ctxMatcher, mock.AnythingOfType("domain.Appeal")).
		Return(preparedGrant, nil).Once()
	h.mockGrantService.EXPECT().
		Revoke(h.ctxMatcher, currentActiveGrant.ID, domain.SystemActorName, appeal.RevokeReasonForExtension,
			mock.AnythingOfType("grant.Option"), mock.AnythingOfType("grant.Option"),
		).
		Return(preparedGrant, nil).Once()

	h.mockRepository.EXPECT().
		BulkUpsert(h.ctxMatcher, expectedAppealsInsertionParam).
		Return(nil).
		Run(func(_a0 context.Context, appeals []*domain.Appeal) {
			for i, a := range appeals {
				a.ID = expectedResult[i].ID
				for j, approval := range a.Approvals {
					approval.ID = expectedResult[i].Approvals[j].ID
				}
			}
		}).Once()
	h.mockNotifier.EXPECT().Notify(h.ctxMatcher, mock.Anything).Return(nil).Once()
	h.mockAuditLogger.EXPECT().Log(mock.Anything, appeal.AuditKeyBulkInsert, mock.Anything).Return(nil).Once()

	actualError := h.service.Create(context.Background(), appeals)

	s.Nil(actualError)
	s.Equal(expectedResult, appeals)
}

func (s *ServiceTestSuite) TestCreateAppeal__WithAdditionalAppeals() {
	h := newServiceTestHelper()
	defer h.assertExpectations(s.T())
	providerType := "test-provider-type"
	providerURN := "test-provider-urn"
	resourceType := "test-resource-type"
	targetResource := &domain.ResourceIdentifier{
		ID: "test-resource-id-2",
	}
	targetRole := "test-role-1"

	resources := []*domain.Resource{
		{
			ID:           "test-resource-id-1",
			URN:          "test-resource-urn-1",
			Type:         resourceType,
			ProviderType: providerType,
			ProviderURN:  providerURN,
		},
		{
			ID:           "test-resource-id-2",
			URN:          "test-resource-urn-2",
			Type:         resourceType,
			ProviderType: providerType,
			ProviderURN:  providerURN,
		},
	}
	policies := []*domain.Policy{
		{
			ID:      "test-policy-id-1",
			Version: 1,
			Steps: []*domain.Step{
				{
					Name:      "test-step-1",
					Strategy:  domain.ApprovalStepStrategyAuto,
					ApproveIf: `true`,
				},
			},
			Requirements: []*domain.Requirement{
				{
					On: &domain.RequirementTrigger{
						Expression: `$appeal.resource.urn == "test-resource-urn-1"`,
					},
					Appeals: []*domain.AdditionalAppeal{
						{
							Resource: targetResource,
							Role:     targetRole,
						},
					},
				},
			},
		},
	}
	providers := []*domain.Provider{
		{
			ID:   "test-provider-id",
			Type: providerType,
			URN:  providerURN,
			Config: &domain.ProviderConfig{
				Resources: []*domain.ResourceConfig{
					{
						Type: resourceType,
						Policy: &domain.PolicyConfig{
							ID:      policies[0].ID,
							Version: int(policies[0].Version),
						},
						Roles: []*domain.Role{
							{
								ID:          "test-role-1",
								Permissions: []interface{}{"test-permission-1"},
							},
						},
					},
				},
			},
		},
	}

	appealsPayload := []*domain.Appeal{
		{
			CreatedBy:  "user@example.com",
			AccountID:  "user@example.com",
			ResourceID: "test-resource-id-1",
			Resource: &domain.Resource{
				ID:           "test-resource-id-1",
				URN:          "test-resource-urn-1",
				Type:         resourceType,
				ProviderType: providerType,
				ProviderURN:  providerURN,
			},
			Role: "test-role-1",
		},
	}

	// 1.a main appeal creation
	expectedResourceFilters := domain.ListResourcesFilter{IDs: []string{appealsPayload[0].Resource.ID}}
	h.mockResourceService.EXPECT().Find(h.ctxMatcher, expectedResourceFilters).Return([]*domain.Resource{resources[0]}, nil).Once()
	h.mockProviderService.EXPECT().Find(h.ctxMatcher).Return(providers, nil).Once()
	h.mockPolicyService.EXPECT().Find(h.ctxMatcher).Return(policies, nil).Once()
	h.mockGrantService.EXPECT().List(h.ctxMatcher, mock.AnythingOfType("domain.ListGrantsFilter")).Return([]domain.Grant{}, nil).Once().Run(func(args mock.Arguments) {
		filter := args.Get(1).(domain.ListGrantsFilter)
		s.Equal([]string{appealsPayload[0].AccountID}, filter.AccountIDs)
		s.Equal([]string{appealsPayload[0].Resource.ID}, filter.ResourceIDs)
		s.Equal([]string{appealsPayload[0].Role}, filter.Roles)
	})
	h.mockRepository.EXPECT().Find(h.ctxMatcher, mock.AnythingOfType("*domain.ListAppealsFilter")).Return([]*domain.Appeal{}, nil).Once()
	h.mockProviderService.EXPECT().ValidateAppeal(h.ctxMatcher, appealsPayload[0], providers[0], policies[0]).Return(nil).Once()
	h.mockProviderService.EXPECT().GetPermissions(h.ctxMatcher, providers[0].Config, appealsPayload[0].Resource.Type, appealsPayload[0].Role).Return([]interface{}{"test-permission-1"}, nil).Once()
	h.mockGrantService.EXPECT().List(h.ctxMatcher, mock.AnythingOfType("domain.ListGrantsFilter")).Return([]domain.Grant{}, nil).Once().Run(func(args mock.Arguments) {
		filter := args.Get(1).(domain.ListGrantsFilter)
		s.Equal([]string{appealsPayload[0].AccountID}, filter.AccountIDs)
		s.Equal([]string{appealsPayload[0].Resource.ID}, filter.ResourceIDs)
	})
	expectedGrant := &domain.Grant{ID: "main-grant"}
	h.mockGrantService.EXPECT().Prepare(h.ctxMatcher, mock.AnythingOfType("domain.Appeal")).Return(expectedGrant, nil).Once().Run(func(args mock.Arguments) {
		appeal := args.Get(1).(domain.Appeal)
		s.Equal(appealsPayload[0].AccountID, appeal.AccountID)
		s.Equal(appealsPayload[0].Role, appeal.Role)
		s.Equal(appealsPayload[0].ResourceID, appeal.ResourceID)
		s.Equal(len(policies[0].Steps), len(appeal.Approvals))
	})
	h.mockPolicyService.EXPECT().GetOne(h.ctxMatcher, policies[0].ID, policies[0].Version).Return(policies[0], nil).Once()

	// 2.a additional appeal creation
	h.mockResourceService.EXPECT().Get(mock.AnythingOfType("*context.cancelCtx"), targetResource).Return(resources[1], nil).Once()
	expectedResourceFilters = domain.ListResourcesFilter{IDs: []string{resources[1].ID}}
	h.mockResourceService.EXPECT().Find(mock.AnythingOfType("*context.cancelCtx"), expectedResourceFilters).Return([]*domain.Resource{resources[1]}, nil).Once()
	h.mockProviderService.EXPECT().Find(mock.AnythingOfType("*context.cancelCtx")).Return(providers, nil).Once()
	h.mockPolicyService.EXPECT().Find(mock.AnythingOfType("*context.cancelCtx")).Return(policies, nil).Once()
	h.mockProviderService.EXPECT().
		IsExclusiveRoleAssignment(mock.Anything, mock.Anything, mock.Anything).
		Return(false).Once()
	h.mockGrantService.EXPECT().List(mock.AnythingOfType("*context.cancelCtx"), mock.AnythingOfType("domain.ListGrantsFilter")).Return([]domain.Grant{}, nil).Once().Run(func(args mock.Arguments) {
		filter := args.Get(1).(domain.ListGrantsFilter)
		s.Equal([]string{appealsPayload[0].AccountID}, filter.AccountIDs)
		s.Equal([]string{targetResource.ID}, filter.ResourceIDs)
		s.Equal([]string{targetRole}, filter.Roles)
	})
	h.mockRepository.EXPECT().Find(mock.AnythingOfType("*context.cancelCtx"), mock.AnythingOfType("*domain.ListAppealsFilter")).Return([]*domain.Appeal{}, nil).Once()
	h.mockProviderService.EXPECT().ValidateAppeal(mock.AnythingOfType("*context.cancelCtx"), mock.AnythingOfType("*domain.Appeal"), providers[0], policies[0]).Return(nil).Once().Run(func(args mock.Arguments) {
		appeal := args.Get(1).(*domain.Appeal)
		s.Equal(appealsPayload[0].AccountID, appeal.AccountID)
		s.Equal(targetRole, appeal.Role)
		s.Equal(targetResource.ID, appeal.ResourceID)
	})
	h.mockProviderService.EXPECT().GetPermissions(mock.AnythingOfType("*context.cancelCtx"), providers[0].Config, resourceType, targetRole).Return([]interface{}{"test-permission-1"}, nil).Once()
	h.mockProviderService.EXPECT().
		IsExclusiveRoleAssignment(mock.Anything, mock.Anything, mock.Anything).
		Return(false).Once()
	h.mockGrantService.EXPECT().List(mock.AnythingOfType("*context.cancelCtx"), mock.AnythingOfType("domain.ListGrantsFilter")).Return([]domain.Grant{}, nil).Once().Run(func(args mock.Arguments) {
		filter := args.Get(1).(domain.ListGrantsFilter)
		s.Equal([]string{appealsPayload[0].AccountID}, filter.AccountIDs)
		s.Equal([]string{targetResource.ID}, filter.ResourceIDs)
	})
	expectedAdditionalGrant := &domain.Grant{ID: "additional-grant"}
	h.mockGrantService.EXPECT().Prepare(mock.AnythingOfType("*context.cancelCtx"), mock.AnythingOfType("domain.Appeal")).Return(expectedAdditionalGrant, nil).Once().Run(func(args mock.Arguments) {
		appeal := args.Get(1).(domain.Appeal)
		s.Equal(appealsPayload[0].AccountID, appeal.AccountID)
		s.Equal(targetRole, appeal.Role)
		s.Equal(targetResource.ID, appeal.ResourceID)
		s.Equal(len(policies[0].Steps), len(appeal.Approvals))
	})
	h.mockPolicyService.EXPECT().GetOne(mock.AnythingOfType("*context.cancelCtx"), policies[0].ID, policies[0].Version).Return(policies[0], nil).Once()

	// 2.b grant access for the additional appeal
	h.mockProviderService.EXPECT().GrantAccess(mock.AnythingOfType("*context.cancelCtx"), mock.AnythingOfType("domain.Grant")).Return(nil).Once().Run(func(args mock.Arguments) {
		grant := args.Get(1).(domain.Grant)
		s.Equal(expectedAdditionalGrant.ID, grant.ID)
	})
	h.mockRepository.EXPECT().BulkUpsert(mock.AnythingOfType("*context.cancelCtx"), mock.AnythingOfType("[]*domain.Appeal")).Return(nil).Once().Run(func(args mock.Arguments) {
		appeals := args.Get(1).([]*domain.Appeal)
		appeal := appeals[0]
		s.Equal(targetResource.ID, appeal.Resource.ID)
	})
	h.mockAuditLogger.EXPECT().Log(mock.AnythingOfType("*context.cancelCtx"), appeal.AuditKeyBulkInsert, mock.Anything).Return(nil).Once()
	h.mockNotifier.EXPECT().Notify(h.ctxMatcher, mock.Anything).Return(nil).Once()

	// 1.b grant access for the main appeal
	h.mockProviderService.EXPECT().GrantAccess(h.ctxMatcher, mock.AnythingOfType("domain.Grant")).Return(nil).Once().Run(func(args mock.Arguments) {
		grant := args.Get(1).(domain.Grant)
		s.Equal(expectedGrant.ID, grant.ID)
	})
	h.mockRepository.EXPECT().BulkUpsert(h.ctxMatcher, mock.AnythingOfType("[]*domain.Appeal")).Return(nil).Once().Run(func(args mock.Arguments) {
		appeals := args.Get(1).([]*domain.Appeal)
		appeal := appeals[0]
		s.Equal(appealsPayload[0].Resource.ID, appeal.Resource.ID)
	})
	h.mockAuditLogger.EXPECT().Log(h.ctxMatcher, appeal.AuditKeyBulkInsert, mock.Anything).Return(nil).Once()
	h.mockNotifier.EXPECT().Notify(h.ctxMatcher, mock.Anything).Return(nil).Once()

	err := h.service.Create(context.Background(), appealsPayload)

	s.NoError(err)
}

func (s *ServiceTestSuite) TestUpdateApproval() {
	appealID := uuid.New().String()
	appeal.TimeNow = func() time.Time {
		return timeNow
	}
	s.Run("should return error if approval action parameter is invalid", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		invalidApprovalActionParameters := []domain.ApprovalAction{
			{
				ApprovalName: "approval_1",
				Actor:        "user@email.com",
				Action:       "name",
			},
			{
				AppealID: appealID,
				Actor:    "user@email.com",
				Action:   "name",
			},
			{
				AppealID:     appealID,
				ApprovalName: "approval_1",
				Actor:        "invalidemail",
				Action:       "name",
			},
			{
				AppealID:     appealID,
				ApprovalName: "approval_1",
				Action:       "name",
			},
			{
				AppealID:     appealID,
				ApprovalName: "approval_1",
				Actor:        "user@email.com",
			},
		}

		for _, param := range invalidApprovalActionParameters {
			actualResult, actualError := h.service.UpdateApproval(context.Background(), param)

			s.Nil(actualResult)
			s.Error(actualError)
		}
	})

	validApprovalActionParam := domain.ApprovalAction{
		AppealID:     appealID,
		ApprovalName: "approval_1",
		Actor:        "user@email.com",
		Action:       "approve",
	}

	s.Run("should return error if got any from repository while getting appeal details", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedError := errors.New("repository error")
		h.mockRepository.EXPECT().GetByID(h.ctxMatcher, mock.Anything).Return(nil, expectedError).Once()

		actualResult, actualError := h.service.UpdateApproval(context.Background(), validApprovalActionParam)

		s.Nil(actualResult)
		s.ErrorIs(actualError, expectedError)
	})

	s.Run("should return error if appeal not found", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedError := appeal.ErrAppealNotFound
		h.mockRepository.EXPECT().GetByID(h.ctxMatcher, mock.Anything).Return(nil, expectedError).Once()

		actualResult, actualError := h.service.UpdateApproval(context.Background(), validApprovalActionParam)

		s.Nil(actualResult)
		s.ErrorIs(actualError, appeal.ErrAppealNotFound)
	})

	s.Run("should return error based on statuses conditions", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		testCases := []struct {
			name          string
			appealStatus  string
			approvals     []*domain.Approval
			expectedError error
		}{
			{
				name:          "appeal not eligible, status: canceled",
				appealStatus:  domain.AppealStatusCanceled,
				expectedError: appeal.ErrAppealNotEligibleForApproval,
			},
			{
				name:          "appeal not eligible, status: approved",
				appealStatus:  domain.AppealStatusApproved,
				expectedError: appeal.ErrAppealNotEligibleForApproval,
			},
			{
				name:          "appeal not eligible, status: rejected",
				appealStatus:  domain.AppealStatusRejected,
				expectedError: appeal.ErrAppealNotEligibleForApproval,
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
				expectedError: appeal.ErrApprovalNotEligibleForAction,
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
				expectedError: appeal.ErrApprovalNotEligibleForAction,
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
				expectedError: appeal.ErrApprovalNotEligibleForAction,
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
				expectedError: appeal.ErrApprovalNotEligibleForAction,
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
				expectedError: appeal.ErrApprovalNotEligibleForAction,
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
				expectedError: appeal.ErrApprovalNotFound,
			},
		}

		for _, tc := range testCases {
			expectedAppeal := &domain.Appeal{
				ID:        validApprovalActionParam.AppealID,
				Status:    tc.appealStatus,
				Approvals: tc.approvals,
			}
			h.mockRepository.EXPECT().
				GetByID(h.ctxMatcher, validApprovalActionParam.AppealID).
				Return(expectedAppeal, nil).Once()

			actualResult, actualError := h.service.UpdateApproval(context.Background(), validApprovalActionParam)

			s.Nil(actualResult)
			s.ErrorIs(actualError, tc.expectedError)
		}
	})

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
			{
				Name:      "approval_2",
				Status:    domain.ApprovalStatusBlocked,
				Approvers: []string{"user@email.com"},
			},
		},
		PolicyID:      "policy-test",
		PolicyVersion: 1,
	}

	s.Run("should return error if got any from approvalService.AdvanceApproval", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		h.mockRepository.EXPECT().
			GetByID(h.ctxMatcher, mock.Anything).
			Return(expectedAppeal, nil).Once()
		expectedError := errors.New("unexpected error")

		h.mockPolicyService.EXPECT().GetOne(mock.Anything, mock.Anything, mock.Anything).Return(nil, expectedError).Once()

		actualResult, actualError := h.service.UpdateApproval(context.Background(), validApprovalActionParam)

		s.ErrorIs(actualError, expectedError)
		s.Nil(actualResult)
	})

	s.Run("should terminate existing active grant if present", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		action := domain.ApprovalAction{
			AppealID:     appealID,
			ApprovalName: "test-approval-step",
			Action:       "approve",
			Actor:        "approver@example.com",
		}
		appealDetails := &domain.Appeal{
			ID:         appealID,
			AccountID:  "user@example.com",
			ResourceID: "1",
			Role:       "test-role",
			Status:     domain.AppealStatusPending,
			Approvals: []*domain.Approval{
				{
					Name:      "test-approval-step",
					Status:    domain.ApprovalStatusPending,
					Approvers: []string{"approver@example.com"},
				},
			},
			Resource: &domain.Resource{
				ID: "1",
			},
		}
		existingGrants := []domain.Grant{
			{
				ID:         "2",
				Status:     domain.GrantStatusActive,
				AccountID:  "user@example.com",
				ResourceID: "1",
				Role:       "test-role",
			},
		}
		expectedRevokedGrant := &domain.Grant{}
		*expectedRevokedGrant = existingGrants[0]
		expectedRevokedGrant.Status = domain.GrantStatusInactive

		h.mockRepository.EXPECT().
			GetByID(h.ctxMatcher, mock.Anything).
			Return(appealDetails, nil).Once()

		h.mockPolicyService.EXPECT().GetOne(mock.Anything, mock.Anything, mock.Anything).Return(&domain.Policy{}, nil).Once()
		h.mockProviderService.EXPECT().
			IsExclusiveRoleAssignment(mock.Anything, mock.Anything, mock.Anything).
			Return(false).Once()
		h.mockGrantService.EXPECT().
			List(mock.Anything, mock.Anything).Return(existingGrants, nil).Once()
		expectedNewGrant := &domain.Grant{
			Status:     domain.GrantStatusActive,
			AccountID:  appealDetails.AccountID,
			ResourceID: appealDetails.ResourceID,
		}
		h.mockGrantService.EXPECT().
			Prepare(mock.Anything, mock.Anything).Return(expectedNewGrant, nil).Once()
		h.mockGrantService.EXPECT().
			Revoke(mock.Anything, expectedRevokedGrant.ID, domain.SystemActorName,
				appeal.RevokeReasonForExtension, mock.Anything, mock.Anything).
			Return(expectedNewGrant, nil).Once()
		h.mockRepository.EXPECT().Update(h.ctxMatcher, appealDetails).Return(nil).Once()
		h.mockNotifier.EXPECT().Notify(h.ctxMatcher, mock.Anything).Return(nil).Once()
		h.mockAuditLogger.EXPECT().Log(mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Once()

		_, actualError := h.service.UpdateApproval(context.Background(), action)

		s.Nil(actualError)
	})

	s.Run("should return updated appeal on success", func() {
		creator := "creator@email.com"
		user := "user@email.com"
		dummyResource := &domain.Resource{
			ID:           "1",
			URN:          "urn",
			Name:         "test-resource-name",
			ProviderType: "test-provider",
		}
		testCases := []struct {
			name                   string
			expectedApprovalAction domain.ApprovalAction
			expectedAppealDetails  *domain.Appeal
			expectedResult         *domain.Appeal
			expectedNotifications  []domain.Notification
			expectedGrant          *domain.Grant
		}{
			{
				name:                   "approve",
				expectedApprovalAction: validApprovalActionParam,
				expectedAppealDetails: &domain.Appeal{
					ID:         validApprovalActionParam.AppealID,
					AccountID:  "user@email.com",
					CreatedBy:  creator,
					ResourceID: "1",
					Role:       "test-role",
					Resource: &domain.Resource{
						ID:           "1",
						URN:          "urn",
						Name:         "test-resource-name",
						ProviderType: "test-provider",
					},
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
					ID:         validApprovalActionParam.AppealID,
					AccountID:  "user@email.com",
					CreatedBy:  creator,
					ResourceID: "1",
					Role:       "test-role",
					Resource:   dummyResource,
					Status:     domain.AppealStatusApproved,
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
					Grant: &domain.Grant{
						Status:      domain.GrantStatusActive,
						AccountID:   "user@email.com",
						AccountType: domain.DefaultAppealAccountType,
						ResourceID:  "1",
						Resource:    dummyResource,
						Role:        "test-role",
						IsPermanent: true,
					},
				},
				expectedGrant: &domain.Grant{
					Status:      domain.GrantStatusActive,
					AccountID:   "user@email.com",
					AccountType: domain.DefaultAppealAccountType,
					ResourceID:  "1",
					Resource:    dummyResource,
					Role:        "test-role",
					IsPermanent: true,
				},
				expectedNotifications: []domain.Notification{
					{
						User: creator,
						Message: domain.NotificationMessage{
							Type: domain.NotificationTypeAppealApproved,
							Variables: map[string]interface{}{
								"resource_name": "test-resource-name (test-provider: urn)",
								"role":          "test-role",
							},
						},
					},
				},
			},
			{
				name: "reject",
				expectedApprovalAction: domain.ApprovalAction{
					AppealID:     appealID,
					ApprovalName: "approval_1",
					Actor:        "user@email.com",
					Action:       domain.AppealActionNameReject,
					Reason:       "test-reason",
				},
				expectedAppealDetails: &domain.Appeal{
					ID:         validApprovalActionParam.AppealID,
					AccountID:  "user@email.com",
					CreatedBy:  creator,
					ResourceID: "1",
					Role:       "test-role",
					Resource: &domain.Resource{
						ID:           "1",
						URN:          "urn",
						Name:         "test-resource-name",
						ProviderType: "test-provider",
					},
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
					ID:         validApprovalActionParam.AppealID,
					AccountID:  "user@email.com",
					CreatedBy:  creator,
					ResourceID: "1",
					Role:       "test-role",
					Resource: &domain.Resource{
						ID:           "1",
						URN:          "urn",
						Name:         "test-resource-name",
						ProviderType: "test-provider",
					},
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
							Reason:    "test-reason",
							UpdatedAt: timeNow,
						},
					},
				},
				expectedNotifications: []domain.Notification{
					{
						User: creator,
						Message: domain.NotificationMessage{
							Type: domain.NotificationTypeAppealRejected,
							Variables: map[string]interface{}{
								"resource_name": "test-resource-name (test-provider: urn)",
								"role":          "test-role",
							},
						},
					},
				},
			},
			{
				name: "reject in the middle step",
				expectedApprovalAction: domain.ApprovalAction{
					AppealID:     appealID,
					ApprovalName: "approval_1",
					Actor:        user,
					Action:       domain.AppealActionNameReject,
				},
				expectedAppealDetails: &domain.Appeal{
					ID:         validApprovalActionParam.AppealID,
					AccountID:  "user@email.com",
					CreatedBy:  creator,
					ResourceID: "1",
					Role:       "test-role",
					Resource: &domain.Resource{
						ID:           "1",
						URN:          "urn",
						Name:         "test-resource-name",
						ProviderType: "test-provider",
					},
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
					ID:         validApprovalActionParam.AppealID,
					AccountID:  "user@email.com",
					CreatedBy:  creator,
					ResourceID: "1",
					Role:       "test-role",
					Resource: &domain.Resource{
						ID:           "1",
						URN:          "urn",
						Name:         "test-resource-name",
						ProviderType: "test-provider",
					},
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
				expectedNotifications: []domain.Notification{
					{
						User: creator,
						Message: domain.NotificationMessage{
							Type: domain.NotificationTypeAppealRejected,
							Variables: map[string]interface{}{
								"resource_name": "test-resource-name (test-provider: urn)",
								"role":          "test-role",
							},
						},
					},
				},
			},
			{
				name: "should notify the next approvers if there's still manual approvals remaining ahead after approved",
				expectedApprovalAction: domain.ApprovalAction{
					AppealID:     validApprovalActionParam.AppealID,
					ApprovalName: "approval_0",
					Actor:        user,
					Action:       domain.AppealActionNameApprove,
				},
				expectedAppealDetails: &domain.Appeal{
					ID:         validApprovalActionParam.AppealID,
					AccountID:  "user@email.com",
					CreatedBy:  creator,
					ResourceID: "1",
					Role:       "test-role",
					Resource: &domain.Resource{
						ID:           "1",
						URN:          "urn",
						Name:         "test-resource-name",
						ProviderType: "test-provider",
					},
					Status: domain.AppealStatusPending,
					Approvals: []*domain.Approval{
						{
							Name:      "approval_0",
							Status:    domain.ApprovalStatusPending,
							Approvers: []string{user},
						},
						{
							Name:   "approval_1",
							Status: domain.ApprovalStatusBlocked,
							Approvers: []string{
								"nextapprover1@email.com",
								"nextapprover2@email.com",
							},
						},
					},
				},
				expectedResult: &domain.Appeal{
					ID:         validApprovalActionParam.AppealID,
					AccountID:  "user@email.com",
					CreatedBy:  creator,
					ResourceID: "1",
					Role:       "test-role",
					Resource: &domain.Resource{
						ID:           "1",
						URN:          "urn",
						Name:         "test-resource-name",
						ProviderType: "test-provider",
					},
					Status: domain.AppealStatusPending,
					Approvals: []*domain.Approval{
						{
							Name:      "approval_0",
							Status:    domain.ApprovalStatusApproved,
							Approvers: []string{user},
							Actor:     &user,
							UpdatedAt: timeNow,
						},
						{
							Name:   "approval_1",
							Status: domain.ApprovalStatusPending,
							Approvers: []string{
								"nextapprover1@email.com",
								"nextapprover2@email.com",
							},
						},
					},
				},
				expectedNotifications: []domain.Notification{
					{
						User: "nextapprover1@email.com",
						Message: domain.NotificationMessage{
							Type: domain.NotificationTypeApproverNotification,
							Variables: map[string]interface{}{
								"resource_name": "test-resource-name (test-provider: urn)",
								"role":          "test-role",
								"requestor":     creator,
								"appeal_id":     validApprovalActionParam.AppealID,
							},
						},
					},
					{
						User: "nextapprover2@email.com",
						Message: domain.NotificationMessage{
							Type: domain.NotificationTypeApproverNotification,
							Variables: map[string]interface{}{
								"resource_name": "test-resource-name (test-provider: urn)",
								"role":          "test-role",
								"requestor":     creator,
								"appeal_id":     validApprovalActionParam.AppealID,
							},
						},
					},
				},
			},
		}
		for _, tc := range testCases {
			s.Run(tc.name, func() {
				h := newServiceTestHelper()
				defer h.assertExpectations(s.T())

				h.mockRepository.EXPECT().
					GetByID(h.ctxMatcher, validApprovalActionParam.AppealID).
					Return(tc.expectedAppealDetails, nil).Once()

				if tc.expectedApprovalAction.Action == domain.AppealActionNameApprove &&
					tc.expectedAppealDetails.Policy == nil {
					mockPolicy := &domain.Policy{
						Steps: []*domain.Step{
							{Name: "step-1"},
							{Name: "step-2"},
						},
					}
					h.mockPolicyService.EXPECT().
						GetOne(mock.Anything, tc.expectedAppealDetails.PolicyID, tc.expectedAppealDetails.PolicyVersion).
						Return(mockPolicy, nil).Once()
					tc.expectedResult.Policy = mockPolicy
				}

				if tc.expectedGrant != nil {
					h.mockProviderService.EXPECT().
						IsExclusiveRoleAssignment(mock.Anything, mock.Anything, mock.Anything).
						Return(false).Once()
					h.mockGrantService.EXPECT().
						List(mock.Anything, domain.ListGrantsFilter{
							AccountIDs:  []string{tc.expectedAppealDetails.AccountID},
							ResourceIDs: []string{tc.expectedAppealDetails.ResourceID},
							Statuses:    []string{string(domain.GrantStatusActive)},
							Permissions: tc.expectedAppealDetails.Permissions,
						}).Return([]domain.Grant{}, nil).Once()
					h.mockGrantService.EXPECT().
						Prepare(mock.Anything, mock.Anything).Return(tc.expectedGrant, nil).Once()

					h.mockProviderService.EXPECT().GrantAccess(mock.Anything, *tc.expectedGrant).Return(nil).Once()
				}

				h.mockRepository.EXPECT().Update(h.ctxMatcher, tc.expectedResult).Return(nil).Once()
				h.mockNotifier.EXPECT().Notify(h.ctxMatcher, mock.Anything).Return(nil).Once()
				h.mockAuditLogger.EXPECT().Log(mock.Anything, mock.Anything, mock.Anything).
					Return(nil).Once()

				actualResult, actualError := h.service.UpdateApproval(context.Background(), tc.expectedApprovalAction)

				s.NoError(actualError)
				tc.expectedResult.Policy = actualResult.Policy
				s.Equal(tc.expectedResult, actualResult)
			})
		}
	})
}

func (s *ServiceTestSuite) TestGrantAccessToProvider() {
	s.Run("should return error when policy is not found", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedError := errors.New("retrieving policy: not found")

		h.mockPolicyService.EXPECT().GetOne(mock.Anything, "policy_1", uint(1)).Return(nil, errors.New("not found")).Once()

		actualError := h.service.GrantAccessToProvider(context.Background(), &domain.Appeal{
			PolicyID:      "policy_1",
			PolicyVersion: 1,
		})

		s.EqualError(actualError, expectedError.Error())
	})

	s.Run("handle appeal requirements", func() {
		s.Run("matching error", func() {
			h := newServiceTestHelper()
			defer h.assertExpectations(s.T())
			expectedError := errors.New("handling appeal requirements: evaluating requirements[1]: error parsing regexp: missing closing ]: `[InvalidRegex`")

			h.mockPolicyService.
				On("GetOne", mock.Anything, "policy_1", uint(1)).
				Return(&domain.Policy{
					ID:      "policy_1",
					Version: 1,
					Requirements: []*domain.Requirement{
						{
							On: &domain.RequirementTrigger{
								ProviderType: "not-matching",
							},
						},
						{
							On: &domain.RequirementTrigger{
								ProviderType: "[InvalidRegex",
							},
						},
					},
				}, nil).Once()

			actualError := h.service.GrantAccessToProvider(context.Background(), &domain.Appeal{
				PolicyID:      "policy_1",
				PolicyVersion: 1,
				Resource: &domain.Resource{
					ProviderType: "example-provider",
				},
			})
			s.EqualError(actualError, expectedError.Error())
		})
	})

	s.Run("should return error when grant access to provider fails", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedError := errors.New("granting access: error")

		h.mockPolicyService.
			On("GetOne", mock.Anything, "policy_1", uint(1)).
			Return(&domain.Policy{
				ID:      "policy_1",
				Version: 1,
			}, nil).Once()

		h.mockProviderService.
			On("GrantAccess", mock.Anything, mock.Anything).
			Return(fmt.Errorf("error")).Once()

		actualError := h.service.GrantAccessToProvider(context.Background(), &domain.Appeal{
			PolicyID:      "policy_1",
			PolicyVersion: 1,
			Grant:         &domain.Grant{},
		})
		s.EqualError(actualError, expectedError.Error())
	})

	s.Run("should be able to grant access", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		h.mockPolicyService.
			On("GetOne", mock.Anything, "policy_1", uint(1)).
			Return(&domain.Policy{
				ID:      "policy_1",
				Version: 1,
			}, nil).Once()

		h.mockProviderService.
			On("GrantAccess", mock.Anything, mock.Anything).
			Return(nil).Once()

		actualError := h.service.GrantAccessToProvider(context.Background(), &domain.Appeal{
			PolicyID:      "policy_1",
			PolicyVersion: 1,
			Grant:         &domain.Grant{},
		})
		s.Nil(actualError, actualError)
	})
}

func (s *ServiceTestSuite) TestCancel() {
	s.Run("should return error if appeal id is empty", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		id := ""
		expectedErr := appeal.ErrAppealIDEmptyParam

		actualResult, actualErr := h.service.Cancel(context.Background(), id)
		s.Nil(actualResult)
		s.EqualError(actualErr, expectedErr.Error())
	})

	s.Run("should return error if appeal id is invalid", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		id := "abc"
		expectedErr := appeal.InvalidError{AppealID: id}

		actualResult, actualErr := h.service.Cancel(context.Background(), id)
		s.Nil(actualResult)
		s.EqualError(actualErr, expectedErr.Error())
	})
}

func (s *ServiceTestSuite) TestAddApprover() {
	s.Run("should return appeal on success", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		appealID := uuid.New().String()
		approvalID := uuid.New().String()
		approvalName := "test-approval-name"
		newApprover := "user@example.com"

		testCases := []struct {
			name, appealID, approvalID, newApprover string
		}{
			{
				name:     "with approval ID",
				appealID: appealID, approvalID: approvalID, newApprover: newApprover,
			},
			{
				name:     "with approval name",
				appealID: appealID, approvalID: approvalName, newApprover: newApprover,
			},
		}

		for _, tc := range testCases {
			s.Run(tc.name, func() {
				expectedAppeal := &domain.Appeal{
					ID:     appealID,
					Status: domain.AppealStatusPending,
					Approvals: []*domain.Approval{
						{
							ID:     approvalID,
							Name:   approvalName,
							Status: domain.ApprovalStatusPending,
							Approvers: []string{
								"existing.approver@example.com",
							},
						},
					},
					Resource: &domain.Resource{},
				}
				expectedApproval := &domain.Approval{
					ID:     approvalID,
					Name:   approvalName,
					Status: domain.ApprovalStatusPending,
					Approvers: []string{
						"existing.approver@example.com",
						tc.newApprover,
					},
				}
				h.mockRepository.EXPECT().
					GetByID(h.ctxMatcher, appealID).
					Return(expectedAppeal, nil).Once()
				h.mockApprovalService.EXPECT().
					AddApprover(h.ctxMatcher, approvalID, newApprover).
					Return(nil).Once()
				h.mockAuditLogger.EXPECT().
					Log(h.ctxMatcher, appeal.AuditKeyAddApprover, expectedApproval).Return(nil).Once()
				h.mockNotifier.EXPECT().
					Notify(h.ctxMatcher, mock.Anything).
					Run(func(ctx context.Context, notifications []domain.Notification) {
						s.Len(notifications, 1)
						n := notifications[0]
						s.Equal(tc.newApprover, n.User)
						s.Equal(domain.NotificationTypeApproverNotification, n.Message.Type)
					}).
					Return(nil).Once()

				actualAppeal, actualError := h.service.AddApprover(context.Background(), appealID, approvalID, newApprover)

				s.NoError(actualError)
				s.Equal(expectedApproval, actualAppeal.Approvals[0])

			})
		}
	})

	s.Run("params validation", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		testCases := []struct {
			name, appealID, approvalID, email string
		}{
			{
				name:       "empty appealID",
				approvalID: uuid.New().String(),
				email:      "user@example.com",
			},
			{
				name:     "empty approvalID",
				appealID: uuid.New().String(),
				email:    "user@example.com",
			},
			{
				name:       "empty email",
				appealID:   uuid.New().String(),
				approvalID: uuid.New().String(),
			},
			{
				name:       "invalid email",
				appealID:   uuid.New().String(),
				approvalID: uuid.New().String(),
				email:      "invalid email",
			},
		}

		for _, tc := range testCases {
			s.Run(tc.name, func() {
				appeal, err := h.service.AddApprover(context.Background(), tc.appealID, tc.approvalID, tc.email)

				s.Nil(appeal)
				s.Error(err)
			})
		}
	})

	s.Run("should return error if getting appeal details returns an error", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedError := errors.New("unexpected error")
		h.mockRepository.EXPECT().
			GetByID(h.ctxMatcher, mock.Anything).
			Return(nil, expectedError).Once()

		appeal, err := h.service.AddApprover(context.Background(), uuid.New().String(), uuid.New().String(), "user@example.com")

		s.Nil(appeal)
		s.ErrorIs(err, expectedError)

	})

	s.Run("should return error if appeal status is not pending", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		approvalID := uuid.New().String()
		expectedError := appeal.ErrUnableToAddApprover
		expectedAppeal := &domain.Appeal{
			Status: domain.AppealStatusApproved,
			Approvals: []*domain.Approval{
				{
					ID: approvalID,
				},
			},
		}
		h.mockRepository.EXPECT().
			GetByID(h.ctxMatcher, mock.Anything).
			Return(expectedAppeal, nil).Once()

		appeal, err := h.service.AddApprover(context.Background(), uuid.New().String(), approvalID, "user@example.com")

		s.Nil(appeal)
		s.ErrorIs(err, expectedError)

	})

	s.Run("should return error if approval not found", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedError := appeal.ErrApprovalNotFound
		expectedAppeal := &domain.Appeal{
			Status: domain.AppealStatusPending,
			Approvals: []*domain.Approval{
				{
					ID: "foobar",
				},
			},
		}
		h.mockRepository.EXPECT().
			GetByID(h.ctxMatcher, mock.Anything).
			Return(expectedAppeal, nil).Once()

		appeal, err := h.service.AddApprover(context.Background(), uuid.New().String(), uuid.New().String(), "user@example.com")

		s.Nil(appeal)
		s.ErrorIs(err, expectedError)

	})

	s.Run("should return error if approval status is not pending or blocked", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedError := appeal.ErrUnableToAddApprover
		approvalID := uuid.New().String()
		expectedAppeal := &domain.Appeal{
			Status: domain.AppealStatusPending,
			Approvals: []*domain.Approval{
				{
					ID:     approvalID,
					Status: domain.ApprovalStatusApproved,
				},
			},
		}
		h.mockRepository.EXPECT().
			GetByID(h.ctxMatcher, mock.Anything).
			Return(expectedAppeal, nil).Once()

		appeal, err := h.service.AddApprover(context.Background(), uuid.New().String(), approvalID, "user@example.com")

		s.Nil(appeal)
		s.ErrorIs(err, expectedError)

	})

	s.Run("should return error if approval is a manual step", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedError := appeal.ErrUnableToAddApprover
		approvalID := uuid.New().String()
		expectedAppeal := &domain.Appeal{
			Status: domain.AppealStatusPending,
			Approvals: []*domain.Approval{
				{
					ID:        approvalID,
					Status:    domain.ApprovalStatusBlocked,
					Approvers: nil,
				},
			},
		}
		h.mockRepository.EXPECT().
			GetByID(h.ctxMatcher, mock.Anything).
			Return(expectedAppeal, nil).Once()

		appeal, err := h.service.AddApprover(context.Background(), uuid.New().String(), approvalID, "user@example.com")

		s.Nil(appeal)
		s.ErrorIs(err, expectedError)

	})

	s.Run("should return error if approval service returns an error when adding the new approver", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedError := errors.New("unexpected error")
		approvalID := uuid.New().String()
		expectedAppeal := &domain.Appeal{
			Status: domain.AppealStatusPending,
			Approvals: []*domain.Approval{
				{
					ID:        approvalID,
					Status:    domain.ApprovalStatusPending,
					Approvers: []string{"approver1@example.com"},
				},
			},
		}
		h.mockRepository.EXPECT().
			GetByID(h.ctxMatcher, mock.Anything).
			Return(expectedAppeal, nil).Once()
		h.mockApprovalService.EXPECT().AddApprover(mock.Anything, mock.Anything, mock.Anything).Return(expectedError).Once()

		appeal, err := h.service.AddApprover(context.Background(), uuid.New().String(), approvalID, "user@example.com")

		s.Nil(appeal)
		s.ErrorIs(err, expectedError)

	})

	s.Run("should return error if the new approver is already exist on the current approval", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedError := appeal.ErrUnableToAddApprover
		approvalID := uuid.New().String()
		expectedAppeal := &domain.Appeal{
			Status: domain.AppealStatusPending,
			Approvals: []*domain.Approval{
				{
					ID:        approvalID,
					Status:    domain.ApprovalStatusPending,
					Approvers: []string{"existing.approver@example.com"},
				},
			},
		}
		h.mockRepository.EXPECT().
			GetByID(h.ctxMatcher, mock.Anything).
			Return(expectedAppeal, nil).Once()

		appeal, err := h.service.AddApprover(context.Background(), uuid.New().String(), approvalID, "existing.approver@example.com")

		s.Nil(appeal)
		s.ErrorIs(err, expectedError)

	})
}

func (s *ServiceTestSuite) TestDeleteApprover() {
	s.Run("should return nil error on success", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		appealID := uuid.New().String()
		approvalID := uuid.New().String()
		approvalName := "test-approval-name"
		approverEmail := "user@example.com"

		testCases := []struct {
			name, appealID, approvalID, newApprover string
		}{
			{
				name:     "with approval ID",
				appealID: appealID, approvalID: approvalID, newApprover: approverEmail,
			},
			{
				name:     "with approval name",
				appealID: appealID, approvalID: approvalName, newApprover: approverEmail,
			},
		}

		for _, tc := range testCases {
			s.Run(tc.name, func() {
				expectedAppeal := &domain.Appeal{
					ID:     appealID,
					Status: domain.AppealStatusPending,
					Approvals: []*domain.Approval{
						{
							ID:     approvalID,
							Name:   approvalName,
							Status: domain.ApprovalStatusPending,
							Approvers: []string{
								"approver1@example.com",
								tc.newApprover,
							},
						},
					},
					Resource: &domain.Resource{},
				}
				expectedApproval := &domain.Approval{
					ID:     approvalID,
					Name:   approvalName,
					Status: domain.ApprovalStatusPending,
					Approvers: []string{
						"approver1@example.com",
					},
				}
				h.mockRepository.EXPECT().
					GetByID(h.ctxMatcher, appealID).
					Return(expectedAppeal, nil).Once()
				h.mockApprovalService.EXPECT().
					DeleteApprover(h.ctxMatcher, approvalID, approverEmail).
					Return(nil).Once()
				h.mockAuditLogger.EXPECT().
					Log(h.ctxMatcher, appeal.AuditKeyDeleteApprover, expectedApproval).Return(nil).Once()

				actualAppeal, actualError := h.service.DeleteApprover(context.Background(), appealID, approvalID, approverEmail)

				s.NoError(actualError)
				s.Equal(expectedApproval, actualAppeal.Approvals[0])

			})
		}
	})

	s.Run("params validation", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		testCases := []struct {
			name, appealID, approvalID, email string
		}{
			{
				name:       "empty appealID",
				approvalID: uuid.New().String(),
				email:      "user@example.com",
			},
			{
				name:     "empty approvalID",
				appealID: uuid.New().String(),
				email:    "user@example.com",
			},
			{
				name:       "empty email",
				appealID:   uuid.New().String(),
				approvalID: uuid.New().String(),
			},
			{
				name:       "invalid email",
				appealID:   uuid.New().String(),
				approvalID: uuid.New().String(),
				email:      "invalid email",
			},
		}

		for _, tc := range testCases {
			s.Run(tc.name, func() {
				appeal, err := h.service.DeleteApprover(context.Background(), tc.appealID, tc.approvalID, tc.email)

				s.Nil(appeal)
				s.Error(err)
			})
		}
	})

	s.Run("should return error if getting appeal details returns an error", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedError := errors.New("unexpected error")
		h.mockRepository.EXPECT().
			GetByID(h.ctxMatcher, mock.Anything).
			Return(nil, expectedError).Once()

		appeal, err := h.service.DeleteApprover(context.Background(), uuid.New().String(), uuid.New().String(), "user@example.com")

		s.Nil(appeal)
		s.ErrorIs(err, expectedError)

	})

	s.Run("should return error if appeal status is not pending", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		approvalID := uuid.New().String()
		expectedError := appeal.ErrUnableToDeleteApprover
		expectedAppeal := &domain.Appeal{
			Status: domain.AppealStatusApproved,
			Approvals: []*domain.Approval{
				{
					ID: approvalID,
				},
			},
		}
		h.mockRepository.EXPECT().
			GetByID(h.ctxMatcher, mock.Anything).
			Return(expectedAppeal, nil).Once()

		appeal, err := h.service.DeleteApprover(context.Background(), uuid.New().String(), approvalID, "user@example.com")

		s.Nil(appeal)
		s.ErrorIs(err, expectedError)

	})

	s.Run("should return error if approval status is not pending or blocked", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedError := appeal.ErrUnableToDeleteApprover
		approvalID := uuid.New().String()
		expectedAppeal := &domain.Appeal{
			Status: domain.AppealStatusPending,
			Approvals: []*domain.Approval{
				{
					ID:     approvalID,
					Status: domain.ApprovalStatusApproved,
				},
			},
		}
		h.mockRepository.EXPECT().
			GetByID(h.ctxMatcher, mock.Anything).
			Return(expectedAppeal, nil).Once()

		appeal, err := h.service.DeleteApprover(context.Background(), uuid.New().String(), approvalID, "user@example.com")

		s.Nil(appeal)
		s.ErrorIs(err, expectedError)
	})

	s.Run("should return error if approval is a manual step", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedError := appeal.ErrUnableToDeleteApprover
		approvalID := uuid.New().String()
		expectedAppeal := &domain.Appeal{
			Status: domain.AppealStatusPending,
			Approvals: []*domain.Approval{
				{
					ID:        approvalID,
					Status:    domain.ApprovalStatusBlocked,
					Approvers: nil,
				},
			},
		}
		h.mockRepository.EXPECT().
			GetByID(h.ctxMatcher, mock.Anything).
			Return(expectedAppeal, nil).Once()

		appeal, err := h.service.DeleteApprover(context.Background(), uuid.New().String(), approvalID, "user@example.com")

		s.Nil(appeal)
		s.ErrorIs(err, expectedError)
	})

	s.Run("should return error if there's only one approver", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedError := appeal.ErrUnableToDeleteApprover
		approvalID := uuid.New().String()
		expectedAppeal := &domain.Appeal{
			Status: domain.AppealStatusPending,
			Approvals: []*domain.Approval{
				{
					ID:        approvalID,
					Status:    domain.ApprovalStatusBlocked,
					Approvers: []string{"approver1@example.com"},
				},
			},
		}
		h.mockRepository.EXPECT().
			GetByID(h.ctxMatcher, mock.Anything).
			Return(expectedAppeal, nil).Once()

		appeal, err := h.service.DeleteApprover(context.Background(), uuid.New().String(), approvalID, "user@example.com")

		s.Nil(appeal)
		s.ErrorIs(err, expectedError)
	})

	s.Run("should return error if approval service returns an error when deleting the new approver", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedError := appeal.ErrUnableToDeleteApprover
		approvalID := uuid.New().String()
		approverEmail := "user@example.com"
		expectedAppeal := &domain.Appeal{
			Status: domain.AppealStatusPending,
			Approvals: []*domain.Approval{
				{
					ID:        approvalID,
					Status:    domain.ApprovalStatusPending,
					Approvers: []string{"another.approver@example.com", approverEmail},
				},
			},
		}
		h.mockRepository.EXPECT().
			GetByID(h.ctxMatcher, mock.Anything).
			Return(expectedAppeal, nil).Once()
		h.mockApprovalService.EXPECT().
			DeleteApprover(h.ctxMatcher, mock.Anything, mock.Anything).
			Return(expectedError).Once()

		appeal, err := h.service.DeleteApprover(context.Background(), uuid.New().String(), approvalID, approverEmail)

		s.Nil(appeal)
		s.ErrorIs(err, expectedError)
	})
}

func (s *ServiceTestSuite) TestGetAppealsTotalCount() {
	s.Run("should return error if got error from repository", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedError := errors.New("repository error")
		h.mockRepository.EXPECT().
			GetAppealsTotalCount(h.ctxMatcher, mock.Anything).
			Return(0, expectedError).Once()

		actualCount, actualError := h.service.GetAppealsTotalCount(context.Background(), &domain.ListAppealsFilter{})

		s.Zero(actualCount)
		s.EqualError(actualError, expectedError.Error())
	})

	s.Run("should return appeals count from repository", func() {
		h := newServiceTestHelper()
		defer h.assertExpectations(s.T())
		expectedCount := int64(1)
		h.mockRepository.EXPECT().
			GetAppealsTotalCount(h.ctxMatcher, mock.Anything).
			Return(expectedCount, nil).Once()

		actualCount, actualError := h.service.GetAppealsTotalCount(context.Background(), &domain.ListAppealsFilter{})

		s.Equal(expectedCount, actualCount)
		s.NoError(actualError)
	})
}
