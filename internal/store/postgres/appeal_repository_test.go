package postgres_test

import (
	"context"
	"database/sql/driver"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/goto/guardian/core/appeal"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/internal/store/postgres"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/pkg/postgrestest"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/suite"
)

type AppealRepositoryTestSuite struct {
	suite.Suite
	store           *postgres.Store
	pool            *dockertest.Pool
	resource        *dockertest.Resource
	repository      *postgres.AppealRepository
	grantRepository *postgres.GrantRepository

	dummyProvider *domain.Provider
	dummyPolicy   *domain.Policy
	dummyResource *domain.Resource
}

func (s *AppealRepositoryTestSuite) SetupSuite() {
	var err error
	logger := log.NewCtxLogger("debug", []string{"test"})
	s.store, s.pool, s.resource, err = postgrestest.NewTestStore(logger)
	if err != nil {
		s.T().Fatal(err)
	}

	ctx := context.Background()

	s.repository = postgres.NewAppealRepository(s.store.DB())

	s.grantRepository = postgres.NewGrantRepository(s.store.DB())

	s.dummyPolicy = &domain.Policy{
		ID:      "policy_test",
		Version: 1,
	}
	policyRepository := postgres.NewPolicyRepository(s.store.DB())
	err = policyRepository.Create(ctx, s.dummyPolicy)
	s.Require().NoError(err)

	s.dummyProvider = &domain.Provider{
		Type: "provider_test",
		URN:  "provider_urn_test",
		Config: &domain.ProviderConfig{
			Resources: []*domain.ResourceConfig{
				{
					Type: "resource_type_test",
					Policy: &domain.PolicyConfig{
						ID:      s.dummyPolicy.ID,
						Version: int(s.dummyPolicy.Version),
					},
				},
			},
		},
	}
	providerRepository := postgres.NewProviderRepository(s.store.DB())
	err = providerRepository.Create(ctx, s.dummyProvider)
	s.Require().NoError(err)

	s.dummyResource = &domain.Resource{
		ProviderType: s.dummyProvider.Type,
		ProviderURN:  s.dummyProvider.URN,
		Type:         "resource_type_test",
		URN:          "resource_urn_test",
		Name:         "resource_name_test",
	}
	resourceRepository := postgres.NewResourceRepository(s.store.DB())
	err = resourceRepository.BulkUpsert(ctx, []*domain.Resource{s.dummyResource})
	s.Require().NoError(err)
}

func (s *AppealRepositoryTestSuite) TearDownSuite() {
	// Clean tests
	db, err := s.store.DB().DB()
	if err != nil {
		s.T().Fatal(err)
	}
	err = db.Close()
	if err != nil {
		s.T().Fatal(err)
	}

	err = postgrestest.PurgeTestDocker(s.pool, s.resource)
	if err != nil {
		s.T().Fatal(err)
	}
}

func (s *AppealRepositoryTestSuite) TestGetByID() {
	s.Run("should return error if record not found", func() {
		someID := uuid.New().String()
		expectedError := appeal.ErrAppealNotFound

		actualResult, actualError := s.repository.GetByID(context.Background(), someID)

		s.Nil(actualResult)
		s.EqualError(actualError, expectedError.Error())
	})

	s.Run("should return records on success", func() {
		dummyAppeal := &domain.Appeal{
			ResourceID:    s.dummyResource.ID,
			PolicyID:      s.dummyPolicy.ID,
			PolicyVersion: s.dummyPolicy.Version,
			AccountID:     "user@example.com",
			AccountType:   domain.DefaultAppealAccountType,
			Role:          "role_test",
			Permissions:   []string{"permission_test"},
			CreatedBy:     "user@example.com",
		}

		ctx := context.Background()
		err := s.repository.BulkUpsert(ctx, []*domain.Appeal{dummyAppeal})
		s.Require().NoError(err)

		actualRecord, actualError := s.repository.GetByID(ctx, dummyAppeal.ID)

		s.Nil(actualError)
		s.Equal(dummyAppeal.ID, actualRecord.ID)
	})

	s.Run("should run query based on filters", func() {
		timeNowPlusAnHour := time.Now().Add(time.Hour)
		dummyAppeals := []*domain.Appeal{
			{
				ResourceID:    s.dummyResource.ID,
				PolicyID:      s.dummyPolicy.ID,
				PolicyVersion: s.dummyPolicy.Version,
				AccountID:     "user@example.com",
				AccountType:   domain.DefaultAppealAccountType,
				Role:          "role_test",
				Status:        domain.AppealStatusApproved,
				Permissions:   []string{"permission_test"},
				CreatedBy:     "user@example.com",
				Options: &domain.AppealOptions{
					ExpirationDate: &time.Time{},
				},
			},
			{
				ResourceID:    s.dummyResource.ID,
				PolicyID:      s.dummyPolicy.ID,
				PolicyVersion: s.dummyPolicy.Version,
				AccountID:     "user2@example.com",
				AccountType:   domain.DefaultAppealAccountType,
				Status:        domain.AppealStatusCanceled,
				Role:          "role_test",
				Permissions:   []string{"permission_test_2"},
				CreatedBy:     "user2@example.com",
				Options: &domain.AppealOptions{
					ExpirationDate: &timeNowPlusAnHour,
				},
			},
		}
		testCases := []struct {
			filters        *domain.ListAppealsFilter
			expectedArgs   []driver.Value
			expectedResult []*domain.Appeal
		}{
			{
				filters: &domain.ListAppealsFilter{
					Q: "user",
				},
				expectedResult: []*domain.Appeal{dummyAppeals[0], dummyAppeals[1]},
			},
			{
				filters: &domain.ListAppealsFilter{
					AccountTypes: []string{"x-account-type"},
				},
				expectedResult: []*domain.Appeal{dummyAppeals[0], dummyAppeals[1]},
			},
		}

		for _, tc := range testCases {
			_, actualError := s.repository.Find(context.Background(), tc.filters)
			s.Nil(actualError)
		}
	})
}

func (s *AppealRepositoryTestSuite) TestGetAppealsTotalCount() {
	dummyAppeals := []*domain.Appeal{
		{
			ResourceID:    s.dummyResource.ID,
			PolicyID:      s.dummyPolicy.ID,
			PolicyVersion: s.dummyPolicy.Version,
			AccountID:     "user@example.com",
			AccountType:   domain.DefaultAppealAccountType,
			Role:          "role_test",
			Status:        domain.AppealStatusApproved,
			Permissions:   []string{"permission_test"},
			CreatedBy:     "user@example.com",
		},
	}

	err := s.repository.BulkUpsert(context.Background(), dummyAppeals)
	s.Require().NoError(err)

	s.Run("should return 0", func() {
		_, actualError := s.repository.GetAppealsTotalCount(context.Background(), &domain.ListAppealsFilter{})
		s.Nil(actualError)
	})

	s.Run("Should always return total count on any size and any offset on success", func() {
		testCases := []struct {
			filters domain.ListAppealsFilter
		}{
			{
				filters: domain.ListAppealsFilter{
					Size:   1,
					Offset: 0,
				},
			},
			{
				filters: domain.ListAppealsFilter{
					Size:   1,
					Offset: 1,
				},
			},
		}
		for _, tc := range testCases {
			total, actualError := s.repository.GetAppealsTotalCount(context.Background(), &tc.filters)
			s.NotNil(total)
			s.Nil(actualError)
		}
	})
}

func (s *AppealRepositoryTestSuite) TestFind() {
	timeNowPlusAnHour := time.Now().Add(time.Hour)
	dummyAppeals := []*domain.Appeal{
		{
			ResourceID:    s.dummyResource.ID,
			PolicyID:      s.dummyPolicy.ID,
			PolicyVersion: s.dummyPolicy.Version,
			AccountID:     "user@example.com",
			AccountType:   domain.DefaultAppealAccountType,
			Role:          "role_test",
			Status:        domain.AppealStatusApproved,
			Permissions:   []string{"permission_test"},
			CreatedBy:     "user@example.com",
			Options: &domain.AppealOptions{
				ExpirationDate: &time.Time{},
			},
		},
		{
			ResourceID:    s.dummyResource.ID,
			PolicyID:      s.dummyPolicy.ID,
			PolicyVersion: s.dummyPolicy.Version,
			AccountID:     "user2@example.com",
			AccountType:   domain.DefaultAppealAccountType,
			Status:        domain.AppealStatusCanceled,
			Role:          "role_test",
			Permissions:   []string{"permission_test_2"},
			CreatedBy:     "user2@example.com",
			Options: &domain.AppealOptions{
				ExpirationDate: &timeNowPlusAnHour,
			},
		},
	}

	err := s.repository.BulkUpsert(context.Background(), dummyAppeals)
	s.Require().NoError(err)

	s.Run("should return error if filters validation returns an error", func() {
		invalidFilters := &domain.ListAppealsFilter{
			Statuses: []string{},
		}

		actualAppeals, actualError := s.repository.Find(context.Background(), invalidFilters)

		s.Error(actualError)
		s.Nil(actualAppeals)
	})

	s.Run("should return error if got any from db", func() {
		expectedError := errors.New("ERROR: invalid input syntax for type uuid: \"not-an-uuid\" (SQLSTATE 22P02)")

		actualResult, actualError := s.repository.Find(context.Background(), &domain.ListAppealsFilter{
			ResourceID: "not-an-uuid",
		})

		s.Nil(actualResult)
		s.EqualError(actualError, expectedError.Error())
	})

	s.Run("should run query with group filters", func() {
		testGroupID1 := "test-group-id-1"
		testGroupID2 := "test-group-id-2"

		groupAppeals := []*domain.Appeal{
			{
				ResourceID:    s.dummyResource.ID,
				PolicyID:      s.dummyPolicy.ID,
				PolicyVersion: s.dummyPolicy.Version,
				AccountID:     "groupuser@example.com",
				AccountType:   domain.DefaultAppealAccountType,
				Role:          "test-role",
				Status:        domain.AppealStatusApproved,
				Permissions:   []string{"test-permission"},
				CreatedBy:     "groupuser@example.com",
				GroupID:       testGroupID1,
				GroupType:     "test-group-type",
			},
			{
				ResourceID:    s.dummyResource.ID,
				PolicyID:      s.dummyPolicy.ID,
				PolicyVersion: s.dummyPolicy.Version,
				AccountID:     "groupuser2@example.com",
				AccountType:   domain.DefaultAppealAccountType,
				Role:          "test-role",
				Status:        domain.AppealStatusPending,
				Permissions:   []string{"test-permission"},
				CreatedBy:     "groupuser2@example.com",
				GroupID:       testGroupID2,
				GroupType:     "another-group-type",
			},
		}

		err := s.repository.BulkUpsert(context.Background(), groupAppeals)
		s.Require().NoError(err)

		testCases := []struct {
			name          string
			filters       *domain.ListAppealsFilter
			expectedCount int
			expectedIDs   []string
		}{
			{
				name: "filter by single group_id",
				filters: &domain.ListAppealsFilter{
					GroupIDs: []string{testGroupID1},
				},
				expectedCount: 1,
				expectedIDs:   []string{groupAppeals[0].ID},
			},
			{
				name: "filter by multiple group_ids",
				filters: &domain.ListAppealsFilter{
					GroupIDs: []string{testGroupID1, testGroupID2},
				},
				expectedCount: 2,
				expectedIDs:   []string{groupAppeals[0].ID, groupAppeals[1].ID},
			},
			{
				name: "filter by group_type",
				filters: &domain.ListAppealsFilter{
					GroupTypes: []string{"test-group-type"},
				},
				expectedCount: 1,
				expectedIDs:   []string{groupAppeals[0].ID},
			},
			{
				name: "filter by group_id and group_type",
				filters: &domain.ListAppealsFilter{
					GroupIDs:   []string{testGroupID1},
					GroupTypes: []string{"test-group-type"},
				},
				expectedCount: 1,
				expectedIDs:   []string{groupAppeals[0].ID},
			},
		}

		for _, tc := range testCases {
			s.Run(tc.name, func() {
				actualAppeals, err := s.repository.Find(context.Background(), tc.filters)
				s.Require().NoError(err)
				s.Equal(tc.expectedCount, len(actualAppeals))

				actualIDs := make([]string, len(actualAppeals))
				for i, appeal := range actualAppeals {
					actualIDs[i] = appeal.ID
				}
				s.ElementsMatch(tc.expectedIDs, actualIDs)
			})
		}
	})

	s.Run("should run query based on filters", func() {
		timeNow := time.Now()
		testCases := []struct {
			filters        *domain.ListAppealsFilter
			expectedArgs   []driver.Value
			expectedResult []*domain.Appeal
		}{
			{
				filters:        &domain.ListAppealsFilter{},
				expectedResult: dummyAppeals,
			},
			{
				filters: &domain.ListAppealsFilter{
					CreatedBy: "user@email.com",
				},
				expectedResult: []*domain.Appeal{dummyAppeals[0]},
			},
			{
				filters: &domain.ListAppealsFilter{
					AccountIDs: []string{"user@email.com"},
				},
				expectedResult: []*domain.Appeal{dummyAppeals[0]},
			},
			{
				filters: &domain.ListAppealsFilter{
					AccountID: "user@email.com",
				},
				expectedResult: []*domain.Appeal{dummyAppeals[0]},
			},
			{
				filters: &domain.ListAppealsFilter{
					Statuses: []string{domain.AppealStatusApproved, domain.AppealStatusPending},
				},
				expectedResult: []*domain.Appeal{dummyAppeals[0]},
			},
			{
				filters: &domain.ListAppealsFilter{
					ResourceID: s.dummyResource.ID,
				},
				expectedResult: dummyAppeals,
			},
			{
				filters: &domain.ListAppealsFilter{
					Role: "test-role",
				},
				expectedResult: dummyAppeals,
			},
			{
				filters: &domain.ListAppealsFilter{
					ExpirationDateLessThan: timeNow,
				},
				expectedResult: []*domain.Appeal{dummyAppeals[0]},
			},
			{
				filters: &domain.ListAppealsFilter{
					ExpirationDateGreaterThan: timeNow,
				},
				expectedResult: []*domain.Appeal{dummyAppeals[0]},
			},
			{
				filters: &domain.ListAppealsFilter{
					ProviderTypes: []string{s.dummyProvider.Type},
				},
				expectedResult: dummyAppeals,
			},
			{
				filters: &domain.ListAppealsFilter{
					ProviderURNs: []string{s.dummyProvider.URN},
				},
				expectedResult: dummyAppeals,
			},
			{
				filters: &domain.ListAppealsFilter{
					ResourceTypes: []string{s.dummyResource.Type},
				},
				expectedResult: dummyAppeals,
			},
			{
				filters: &domain.ListAppealsFilter{
					ResourceURNs: []string{s.dummyResource.URN},
				},
				expectedResult: dummyAppeals,
			},
			{
				filters: &domain.ListAppealsFilter{
					OrderBy: []string{"status"},
				},
				expectedResult: []*domain.Appeal{dummyAppeals[0], dummyAppeals[1]},
			},
			{
				filters: &domain.ListAppealsFilter{
					OrderBy: []string{"updated_at:desc"},
				},
				expectedResult: []*domain.Appeal{dummyAppeals[1], dummyAppeals[0]},
			},
			{
				filters: &domain.ListAppealsFilter{
					Q: "user",
				},
				expectedResult: []*domain.Appeal{dummyAppeals[1], dummyAppeals[0]},
			},
			{
				filters: &domain.ListAppealsFilter{
					AccountTypes: []string{"x-account-type"},
				},
				expectedResult: []*domain.Appeal{dummyAppeals[1], dummyAppeals[0]},
			},
		}

		for _, tc := range testCases {
			_, actualError := s.repository.Find(context.Background(), tc.filters)
			s.Nil(actualError)
		}
	})

	s.Run("Should return an array size and offset of n on success", func() {
		testCases := []struct {
			filters        *domain.ListAppealsFilter
			expectedArgs   []driver.Value
			expectedResult []*domain.Appeal
		}{
			{
				filters: &domain.ListAppealsFilter{
					Size:   1,
					Offset: 0,
				},
				expectedResult: []*domain.Appeal{dummyAppeals[0]},
			},
			{
				filters: &domain.ListAppealsFilter{
					Offset: 1,
				},
				expectedResult: []*domain.Appeal{dummyAppeals[1]},
			},
		}
		for _, tc := range testCases {
			_, actualError := s.repository.Find(context.Background(), tc.filters)
			s.Nil(actualError)
		}
	})
}

func (s *AppealRepositoryTestSuite) TestFind_LabelFiltering() {
	// Setup test data with different label combinations
	appealsWithLabels := []*domain.Appeal{
		{
			ResourceID:    s.dummyResource.ID,
			PolicyID:      s.dummyPolicy.ID,
			PolicyVersion: s.dummyPolicy.Version,
			AccountID:     "label-user1@example.com",
			AccountType:   domain.DefaultAppealAccountType,
			Role:          "viewer",
			Status:        domain.AppealStatusApproved,
			Permissions:   []string{"read"},
			CreatedBy:     "label-user1@example.com",
			Labels: map[string]string{
				"environment": "production",
				"team":        "data-engineering",
				"cost_center": "CC-1234",
			},
		},
		{
			ResourceID:    s.dummyResource.ID,
			PolicyID:      s.dummyPolicy.ID,
			PolicyVersion: s.dummyPolicy.Version,
			AccountID:     "label-user2@example.com",
			AccountType:   domain.DefaultAppealAccountType,
			Role:          "editor",
			Status:        domain.AppealStatusPending,
			Permissions:   []string{"write"},
			CreatedBy:     "label-user2@example.com",
			Labels: map[string]string{
				"environment": "staging",
				"team":        "analytics",
				"data_layer":  "raw",
			},
		},
		{
			ResourceID:    s.dummyResource.ID,
			PolicyID:      s.dummyPolicy.ID,
			PolicyVersion: s.dummyPolicy.Version,
			AccountID:     "label-user3@example.com",
			AccountType:   domain.DefaultAppealAccountType,
			Role:          "admin",
			Status:        domain.AppealStatusApproved,
			Permissions:   []string{"admin"},
			CreatedBy:     "label-user3@example.com",
			Labels: map[string]string{
				"environment": "production",
				"team":        "analytics",
				"data_layer":  "processed",
			},
		},
		{
			ResourceID:    s.dummyResource.ID,
			PolicyID:      s.dummyPolicy.ID,
			PolicyVersion: s.dummyPolicy.Version,
			AccountID:     "label-user4@example.com",
			AccountType:   domain.DefaultAppealAccountType,
			Role:          "viewer",
			Status:        domain.AppealStatusRejected,
			Permissions:   []string{"read"},
			CreatedBy:     "label-user4@example.com",
			Labels:        nil, // No labels
		},
	}

	err := s.repository.BulkUpsert(context.Background(), appealsWithLabels)
	s.Require().NoError(err)

	s.Run("filter by single label key-value pair", func() {
		filters := &domain.ListAppealsFilter{
			Labels: map[string][]string{
				"environment": {"production"},
			},
		}

		result, err := s.repository.Find(context.Background(), filters)
		s.NoError(err)
		s.NotNil(result)

		// Should return 2 appeals with environment=production
		productionCount := 0
		for _, appeal := range result {
			if appeal.Labels != nil && appeal.Labels["environment"] == "production" {
				productionCount++
			}
		}
		s.GreaterOrEqual(productionCount, 2)
	})

	s.Run("filter by multiple values for same label (OR logic)", func() {
		filters := &domain.ListAppealsFilter{
			Labels: map[string][]string{
				"environment": {"production", "staging"},
			},
		}

		result, err := s.repository.Find(context.Background(), filters)
		s.NoError(err)
		s.NotNil(result)

		// Should return 3 appeals with either environment
		matchCount := 0
		for _, appeal := range result {
			if appeal.Labels != nil {
				env := appeal.Labels["environment"]
				if env == "production" || env == "staging" {
					matchCount++
				}
			}
		}
		s.GreaterOrEqual(matchCount, 3)
	})

	s.Run("filter by multiple label keys (AND logic)", func() {
		filters := &domain.ListAppealsFilter{
			Labels: map[string][]string{
				"environment": {"production"},
				"team":        {"analytics"},
			},
		}

		result, err := s.repository.Find(context.Background(), filters)
		s.NoError(err)
		s.NotNil(result)

		// Should return 1 appeal matching both criteria
		matchCount := 0
		for _, appeal := range result {
			if appeal.Labels != nil &&
				appeal.Labels["environment"] == "production" &&
				appeal.Labels["team"] == "analytics" {
				matchCount++
			}
		}
		s.GreaterOrEqual(matchCount, 1)
	})

	s.Run("filter by label keys only (regardless of value)", func() {
		filters := &domain.ListAppealsFilter{
			LabelKeys: []string{"data_layer"},
		}

		result, err := s.repository.Find(context.Background(), filters)
		s.NoError(err)
		s.NotNil(result)

		// Should return 2 appeals that have data_layer label
		matchCount := 0
		for _, appeal := range result {
			if appeal.Labels != nil {
				if _, exists := appeal.Labels["data_layer"]; exists {
					matchCount++
				}
			}
		}
		s.GreaterOrEqual(matchCount, 2)
	})

	s.Run("filter by multiple label keys (OR logic)", func() {
		filters := &domain.ListAppealsFilter{
			LabelKeys: []string{"cost_center", "data_layer"},
		}

		result, err := s.repository.Find(context.Background(), filters)
		s.NoError(err)
		s.NotNil(result)

		// Should return 3 appeals that have either label key
		matchCount := 0
		for _, appeal := range result {
			if appeal.Labels != nil {
				_, hasCostCenter := appeal.Labels["cost_center"]
				_, hasDataLayer := appeal.Labels["data_layer"]
				if hasCostCenter || hasDataLayer {
					matchCount++
				}
			}
		}
		s.GreaterOrEqual(matchCount, 3)
	})

	s.Run("combine label filters with label key filters", func() {
		filters := &domain.ListAppealsFilter{
			Labels: map[string][]string{
				"team": {"analytics"},
			},
			LabelKeys: []string{"data_layer"},
		}

		result, err := s.repository.Find(context.Background(), filters)
		s.NoError(err)
		s.NotNil(result)

		// Should return appeals in analytics team that have data_layer
		matchCount := 0
		for _, appeal := range result {
			if appeal.Labels != nil {
				_, hasDataLayer := appeal.Labels["data_layer"]
				if appeal.Labels["team"] == "analytics" && hasDataLayer {
					matchCount++
				}
			}
		}
		s.GreaterOrEqual(matchCount, 2)
	})

	s.Run("filter by non-existent label returns empty or no matches", func() {
		filters := &domain.ListAppealsFilter{
			Labels: map[string][]string{
				"nonexistent": {"value"},
			},
		}

		result, err := s.repository.Find(context.Background(), filters)
		s.NoError(err)
		s.NotNil(result)

		// Should not match any of our test appeals
		matchCount := 0
		for _, appeal := range result {
			if appeal.Labels != nil && appeal.Labels["nonexistent"] == "value" {
				matchCount++
			}
		}
		s.Equal(0, matchCount)
	})

	s.Run("empty label filter values should be ignored", func() {
		filters := &domain.ListAppealsFilter{
			Labels: map[string][]string{
				"environment": {}, // Empty values
			},
		}

		result, err := s.repository.Find(context.Background(), filters)
		s.NoError(err)
		s.NotNil(result)
		// Should return all appeals since empty filter is ignored
	})

	s.Run("combine label filters with other filters", func() {
		filters := &domain.ListAppealsFilter{
			Labels: map[string][]string{
				"environment": {"production"},
			},
			Statuses: []string{domain.AppealStatusApproved},
		}

		result, err := s.repository.Find(context.Background(), filters)
		s.NoError(err)
		s.NotNil(result)

		// Should return only approved appeals in production
		for _, appeal := range result {
			if appeal.Labels != nil && appeal.Labels["environment"] == "production" {
				s.Equal(domain.AppealStatusApproved, appeal.Status)
			}
		}
	})
}

func (s *AppealRepositoryTestSuite) TestBulkUpsert() {
	s.Run("should return error if appeals input is invalid", func() {
		invalidAppeals := []*domain.Appeal{
			{
				Details: map[string]interface{}{
					"foo": make(chan int), // invalid value
				},
			},
		}

		actualErr := s.repository.BulkUpsert(context.Background(), invalidAppeals)

		s.EqualError(actualErr, "json: unsupported type: chan int")
	})

	dummyAppeals := []*domain.Appeal{
		{
			ResourceID:    s.dummyResource.ID,
			PolicyID:      s.dummyPolicy.ID,
			PolicyVersion: s.dummyPolicy.Version,
			AccountID:     "user@example.com",
			AccountType:   domain.DefaultAppealAccountType,
			Role:          "role_test",
			Status:        domain.AppealStatusApproved,
			Permissions:   []string{"permission_test"},
			CreatedBy:     "user@example.com",
			Description:   "The answer is 42",
		},
		{
			ResourceID:    s.dummyResource.ID,
			PolicyID:      s.dummyPolicy.ID,
			PolicyVersion: s.dummyPolicy.Version,
			AccountID:     "user2@example.com",
			AccountType:   domain.DefaultAppealAccountType,
			Status:        domain.AppealStatusCanceled,
			Role:          "role_test",
			Permissions:   []string{"permission_test_2"},
			CreatedBy:     "user2@example.com",
		},
	}

	s.Run("should return nil error on success", func() {
		actualError := s.repository.BulkUpsert(context.Background(), dummyAppeals)
		s.Nil(actualError)
	})
}

func (s *AppealRepositoryTestSuite) TestUpdateByID() {
	dummyAppeals := []*domain.Appeal{
		{
			ResourceID:    s.dummyResource.ID,
			PolicyID:      s.dummyPolicy.ID,
			PolicyVersion: s.dummyPolicy.Version,
			AccountID:     "user@example.com",
			AccountType:   domain.DefaultAppealAccountType,
			Role:          "role_test",
			Status:        domain.AppealStatusApproved,
			Permissions:   []string{"permission_test"},
			CreatedBy:     "user@example.com",
		},
		{
			ResourceID:    s.dummyResource.ID,
			PolicyID:      s.dummyPolicy.ID,
			PolicyVersion: s.dummyPolicy.Version,
			AccountID:     "user2@example.com",
			AccountType:   domain.DefaultAppealAccountType,
			Status:        domain.AppealStatusCanceled,
			Role:          "role_test",
			Permissions:   []string{"permission_test_2"},
			CreatedBy:     "user2@example.com",
		},
	}

	ctx := context.Background()
	actualError := s.repository.BulkUpsert(ctx, dummyAppeals)
	s.Nil(actualError)

	s.Run("should return error if Appeal ID is missing", func() {
		err := s.repository.UpdateByID(context.Background(), &domain.Appeal{})
		s.EqualError(err, appeal.ErrAppealIDEmptyParam.Error())
	})

	s.Run("should return error if appeal input is invalid", func() {
		invalidAppeal := &domain.Appeal{
			ID: uuid.New().String(),
			Details: map[string]interface{}{
				"foo": make(chan int), // invalid value
			},
		}

		actualError := s.repository.UpdateByID(context.Background(), invalidAppeal)

		s.EqualError(actualError, "json: unsupported type: chan int")
	})

	s.Run("should update appeal successfully", func() {
		dummyAppeals[0].Revision = 1
		err := s.repository.UpdateByID(context.Background(), dummyAppeals[0])
		s.Require().NoError(err)

		appeals, err := s.repository.GetByID(context.Background(), dummyAppeals[0].ID)
		s.Require().NoError(err)

		s.Equal(appeals.Revision, uint(1))
	})
}

func (s *AppealRepositoryTestSuite) TestUpdate() {
	s.Run("should return error if appeal input is invalid", func() {
		invalidAppeal := &domain.Appeal{
			ID: uuid.New().String(),
			Details: map[string]interface{}{
				"foo": make(chan int), // invalid value
			},
		}

		actualError := s.repository.Update(context.Background(), invalidAppeal)

		s.EqualError(actualError, "json: unsupported type: chan int")
	})

	s.Run("should return error if grant already exists", func() {
		pendingAppeal := &domain.Appeal{
			ID:            uuid.NewString(),
			ResourceID:    s.dummyResource.ID,
			PolicyID:      s.dummyPolicy.ID,
			PolicyVersion: s.dummyPolicy.Version,
			AccountID:     "user@example.com",
			AccountType:   domain.DefaultAppealAccountType,
			Role:          "role_test",
			Permissions:   []string{"permission_test"},
			CreatedBy:     "user@example.com",
			Status:        domain.AppealStatusPending,
		}
		dummyAppealError := s.repository.BulkUpsert(context.Background(), []*domain.Appeal{pendingAppeal})
		s.Require().NoError(dummyAppealError)

		dummyGrants := &domain.Grant{
			Status:      domain.GrantStatusActive,
			AccountID:   "user@example.com",
			ResourceID:  s.dummyResource.ID,
			Permissions: []string{"permission_test"},
		}

		dummyGrantError := s.grantRepository.BulkUpsert(context.Background(), []*domain.Grant{dummyGrants})
		s.Require().NoError(dummyGrantError)

		appealApprovalErr := pendingAppeal.Approve()
		s.Require().NoError(appealApprovalErr)

		pendingAppeal.Grant = &domain.Grant{ //new duplicate grant
			Status:      domain.GrantStatusActive,
			AccountID:   "user@example.com",
			ResourceID:  s.dummyResource.ID,
			Permissions: []string{"permission_test"},
		}

		err := s.repository.Update(context.Background(), pendingAppeal)
		s.ErrorIs(err, domain.ErrDuplicateActiveGrant)
	})

	s.Run("should return nil on success", func() {
		dummyAppeals := []*domain.Appeal{
			{
				ResourceID:    s.dummyResource.ID,
				PolicyID:      s.dummyPolicy.ID,
				PolicyVersion: s.dummyPolicy.Version,
				AccountID:     "user@example.com",
				AccountType:   domain.DefaultAppealAccountType,
				Role:          "role_test",
				Status:        domain.AppealStatusApproved,
				Permissions:   []string{"permission_test"},
				CreatedBy:     "user@example.com",
			},
			{
				ResourceID:    s.dummyResource.ID,
				PolicyID:      s.dummyPolicy.ID,
				PolicyVersion: s.dummyPolicy.Version,
				AccountID:     "user2@example.com",
				AccountType:   domain.DefaultAppealAccountType,
				Status:        domain.AppealStatusCanceled,
				Role:          "role_test",
				Permissions:   []string{"permission_test_2"},
				CreatedBy:     "user2@example.com",
			},
		}

		ctx := context.Background()
		actualError := s.repository.BulkUpsert(ctx, dummyAppeals)
		s.Nil(actualError)

		err := s.repository.Update(ctx, dummyAppeals[0])
		s.Nil(err)
	})
}

func TestAppealRepository(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	suite.Run(t, new(AppealRepositoryTestSuite))
}
