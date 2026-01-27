package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/suite"

	"github.com/goto/guardian/core/policy"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/internal/store/postgres"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/pkg/postgrestest"
)

type PolicyRepositoryTestSuite struct {
	suite.Suite
	store      *postgres.Store
	pool       *dockertest.Pool
	resource   *dockertest.Resource
	repository *postgres.PolicyRepository
}

func (s *PolicyRepositoryTestSuite) SetupSuite() {
	var err error

	logger := log.NewCtxLogger("debug", []string{"test"})
	s.store, s.pool, s.resource, err = postgrestest.NewTestStore(logger)
	if err != nil {
		s.T().Fatal(err)
	}

	s.repository = postgres.NewPolicyRepository(s.store.DB())
}

func (s *PolicyRepositoryTestSuite) TearDownSuite() {
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

func (s *PolicyRepositoryTestSuite) TestCreate() {
	s.Run("should return error if payload is invalid", func() {
		p := &domain.Policy{
			IAM: &domain.IAMConfig{
				Config: make(chan int),
			},
			AppealConfig: &domain.PolicyAppealConfig{
				AllowPermanentAccess:         false,
				AllowActiveAccessExtensionIn: "24h",
				Questions: []domain.Question{
					{
						Key:         "team",
						Question:    "What team are you in?",
						Required:    true,
						Description: "Please provide the name of the team you are in",
					},
					{
						Key:      "purpose",
						Question: "What is the purpose of this access?",
						Required: false,
						Description: "Explain why you need this access. " +
							"This will be used to evaluate your appeal. " +
							"For example, you may need access to a specific project or resource.",
					},
				},
			},
		}
		actualError := s.repository.Create(context.Background(), p)

		s.EqualError(actualError, "serializing policy: json: unsupported type: chan int")
	})

	s.Run("should return nil error on success", func() {
		p := &domain.Policy{
			ID: "test_policy",
		}
		err := s.repository.Create(context.Background(), p)
		s.Nil(err)
		s.NotEmpty(p.ID)
	})
}

func (s *PolicyRepositoryTestSuite) TestFind() {
	err1 := postgrestest.Setup(s.store)
	s.Nil(err1)

	s.Run("should return list of policies on success", func() {
		ctx := context.Background()
		expectedPolicies := []*domain.Policy{
			{
				Version:     1,
				Description: "test_policy",
				AppealConfig: &domain.PolicyAppealConfig{
					AllowPermanentAccess:         false,
					AllowActiveAccessExtensionIn: "24h",
					Questions: []domain.Question{
						{
							Key:         "team",
							Question:    "What team are you in?",
							Required:    true,
							Description: "Please provide the name of the team you are in",
						},
						{
							Key:      "purpose",
							Question: "What is the purpose of this access?",
							Required: false,
							Description: "Explain why you need this access. " +
								"This will be used to evaluate your appeal. " +
								"For example, you may need access to a specific project or resource.",
						},
					},
				},
			},
		}

		for _, pol := range expectedPolicies {
			err := s.repository.Create(ctx, pol)
			s.Nil(err)
		}

		actualPolicies, actualError := s.repository.Find(ctx, domain.ListPoliciesFilter{})

		if diff := cmp.Diff(expectedPolicies, actualPolicies, cmpopts.EquateApproxTime(time.Microsecond)); diff != "" {
			s.T().Errorf("result not match, diff: %v", diff)
		}
		s.Nil(actualError)
	})

	s.Run("should filter by specific policy ID (all versions)", func() {
		ctx := context.Background()

		// Create test policies with multiple versions
		testPolicies := []*domain.Policy{
			{ID: "policy-1", Version: 1, Description: "policy 1 v1"},
			{ID: "policy-1", Version: 2, Description: "policy 1 v2"},
			{ID: "policy-2", Version: 1, Description: "policy 2 v1"},
		}

		for _, p := range testPolicies {
			err := s.repository.Create(ctx, p)
			s.Require().NoError(err)
		}

		// Filter by policy-1 (should return all versions)
		filter := domain.ListPoliciesFilter{
			IDs: []string{"policy-1"},
		}

		result, err := s.repository.Find(ctx, filter)
		s.NoError(err)
		s.Len(result, 2)
		s.Equal("policy-1", result[0].ID)
		s.Equal("policy-1", result[1].ID)
	})

	s.Run("should filter by policy ID with latest version (ID:0)", func() {
		ctx := context.Background()

		testPolicies := []*domain.Policy{
			{ID: "policy-3", Version: 1, Description: "policy 3 v1"},
			{ID: "policy-3", Version: 2, Description: "policy 3 v2"},
			{ID: "policy-3", Version: 3, Description: "policy 3 v3"},
		}

		for _, p := range testPolicies {
			err := s.repository.Create(ctx, p)
			s.Require().NoError(err)
		}

		// Filter by policy-3:0 (should return latest version only)
		filter := domain.ListPoliciesFilter{
			IDs: []string{"policy-3:0"},
		}

		result, err := s.repository.Find(ctx, filter)
		s.NoError(err)
		s.Len(result, 1)
		s.Equal("policy-3", result[0].ID)
		s.Equal(uint(3), result[0].Version)
	})

	s.Run("should filter by policy ID with specific version", func() {
		ctx := context.Background()

		testPolicies := []*domain.Policy{
			{ID: "policy-4", Version: 1, Description: "policy 4 v1"},
			{ID: "policy-4", Version: 2, Description: "policy 4 v2"},
			{ID: "policy-4", Version: 3, Description: "policy 4 v3"},
		}

		for _, p := range testPolicies {
			err := s.repository.Create(ctx, p)
			s.Require().NoError(err)
		}

		// Filter by policy-4:2 (should return version 2 only)
		filter := domain.ListPoliciesFilter{
			IDs: []string{"policy-4:2"},
		}

		result, err := s.repository.Find(ctx, filter)
		s.NoError(err)
		s.Len(result, 1)
		s.Equal("policy-4", result[0].ID)
		s.Equal(uint(2), result[0].Version)
	})

	s.Run("should filter by multiple policy IDs with mixed formats", func() {
		ctx := context.Background()

		testPolicies := []*domain.Policy{
			{ID: "policy-5", Version: 1, Description: "policy 5 v1"},
			{ID: "policy-5", Version: 2, Description: "policy 5 v2"},
			{ID: "policy-6", Version: 1, Description: "policy 6 v1"},
			{ID: "policy-6", Version: 2, Description: "policy 6 v2"},
			{ID: "policy-7", Version: 1, Description: "policy 7 v1"},
		}

		for _, p := range testPolicies {
			err := s.repository.Create(ctx, p)
			s.Require().NoError(err)
		}

		// Filter by mixed formats: policy-5 (all), policy-6:0 (latest), policy-7:1 (specific)
		filter := domain.ListPoliciesFilter{
			IDs: []string{"policy-5", "policy-6:0", "policy-7:1"},
		}

		result, err := s.repository.Find(ctx, filter)
		s.NoError(err)
		s.Len(result, 4) // policy-5 (2 versions) + policy-6 (latest) + policy-7 (v1)

		// Count occurrences
		idVersionCount := make(map[string]int)
		for _, p := range result {
			key := p.ID
			if p.ID == "policy-5" {
				idVersionCount[key]++
			} else if p.ID == "policy-6" {
				s.Equal(uint(2), p.Version) // should be latest
			} else if p.ID == "policy-7" {
				s.Equal(uint(1), p.Version) // should be v1
			}
		}
		s.Equal(2, idVersionCount["policy-5"]) // all versions
	})

	s.Run("should support pagination with size and offset", func() {
		ctx := context.Background()

		testPolicies := []*domain.Policy{
			{ID: "page-policy-1", Version: 1},
			{ID: "page-policy-2", Version: 1},
			{ID: "page-policy-3", Version: 1},
			{ID: "page-policy-4", Version: 1},
			{ID: "page-policy-5", Version: 1},
		}

		for _, p := range testPolicies {
			err := s.repository.Create(ctx, p)
			s.Require().NoError(err)
		}

		// Get first 2 policies
		filter := domain.ListPoliciesFilter{
			IDs:    []string{"page-policy-1", "page-policy-2", "page-policy-3", "page-policy-4", "page-policy-5"},
			Size:   2,
			Offset: 0,
		}

		result, err := s.repository.Find(ctx, filter)
		s.NoError(err)
		s.Len(result, 2)

		// Get next 2 policies
		filter.Offset = 2
		result, err = s.repository.Find(ctx, filter)
		s.NoError(err)
		s.Len(result, 2)

		// Get last policy
		filter.Offset = 4
		result, err = s.repository.Find(ctx, filter)
		s.NoError(err)
		s.Len(result, 1)
	})
}

func (s *PolicyRepositoryTestSuite) TestGetOne() {
	err1 := postgrestest.Setup(s.store)
	s.Nil(err1)

	s.Run("should return error if record not found", func() {
		expectedError := policy.ErrPolicyNotFound

		sampleUUID := uuid.New().String()
		actualResult, actualError := s.repository.GetOne(context.Background(), sampleUUID, 0)

		s.Nil(actualResult)
		s.EqualError(actualError, expectedError.Error())
	})

	s.Run("should pass args based on the version param", func() {
		dummyPolicies := []*domain.Policy{
			{
				ID:      "test-id",
				Version: 0,
			},
			{
				ID:      "test-id",
				Version: 1,
			},
			{
				ID:      "test-id",
				Version: 2,
			},
		}
		for _, p := range dummyPolicies {
			err := s.repository.Create(context.Background(), p)
			s.Require().NoError(err)
		}

		testCases := []struct {
			name            string
			versionParam    uint
			expectedVersion uint
		}{
			{
				name:            "should return latest version if version param is empty",
				expectedVersion: 2,
			},
			{
				name:            "should return expected version",
				versionParam:    1,
				expectedVersion: 1,
			},
		}

		for _, tc := range testCases {
			s.Run(tc.name, func() {
				actualPolicy, actualError := s.repository.GetOne(context.Background(), "test-id", tc.versionParam)

				s.NoError(actualError)
				s.Equal(tc.expectedVersion, actualPolicy.Version)
			})
		}
	})
}

func TestPolicyRepository(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	suite.Run(t, new(PolicyRepositoryTestSuite))
}
