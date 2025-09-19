package postgres_test

import (
	"context"
	"database/sql/driver"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/goto/guardian/core/grant"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/internal/store/postgres"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/pkg/postgrestest"
	"github.com/stretchr/testify/suite"
)

type GrantRepositoryTestSuite struct {
	suite.Suite
	store      *postgres.Store
	pool       *dockertest.Pool
	resource   *dockertest.Resource
	repository *postgres.GrantRepository

	dummyProvider *domain.Provider
	dummyPolicy   *domain.Policy
	dummyResource *domain.Resource
	dummyAppeal   *domain.Appeal
}

func TestGrantRepository(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	suite.Run(t, new(GrantRepositoryTestSuite))
}

func (s *GrantRepositoryTestSuite) SetupSuite() {
	var err error
	logger := log.NewCtxLogger("debug", []string{"test"})
	s.store, s.pool, s.resource, err = postgrestest.NewTestStore(logger)
	if err != nil {
		s.T().Fatal(err)
	}

	s.repository = postgres.NewGrantRepository(s.store.DB())

	ctx := context.Background()

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

	s.dummyAppeal = &domain.Appeal{
		ResourceID:    s.dummyResource.ID,
		PolicyID:      s.dummyPolicy.ID,
		PolicyVersion: s.dummyPolicy.Version,
		AccountID:     "user@example.com",
		AccountType:   domain.DefaultAppealAccountType,
		Role:          "role_test",
		Permissions:   []string{"permission_test"},
		CreatedBy:     "user@example.com",
	}
	appealRepository := postgres.NewAppealRepository(s.store.DB())
	err = appealRepository.BulkUpsert(ctx, []*domain.Appeal{s.dummyAppeal})
	s.Require().NoError(err)
}

func (s *GrantRepositoryTestSuite) AfterTest(suiteName, testName string) {
	// clean grants table
	db, err := s.store.DB().DB()
	if err != nil {
		s.T().Fatal(err)
	}
	if _, err := db.Exec("DELETE FROM grants"); err != nil {
		s.T().Fatal(err)
	}
}

func (s *GrantRepositoryTestSuite) TearDownSuite() {
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

func (s *GrantRepositoryTestSuite) TestGetGrantsTotalCount() {
	dummyGrants := []*domain.Grant{
		{
			Status:      domain.GrantStatusActive,
			AppealID:    s.dummyAppeal.ID,
			AccountID:   s.dummyAppeal.AccountID,
			AccountType: s.dummyAppeal.AccountType,
			ResourceID:  s.dummyAppeal.ResourceID,
			Role:        s.dummyAppeal.Role,
			Permissions: s.dummyAppeal.Permissions,
			CreatedBy:   s.dummyAppeal.CreatedBy,
			IsPermanent: true,
			Source:      domain.GrantSourceImport,
		},
	}
	err := s.repository.BulkInsert(context.Background(), dummyGrants)
	s.Require().NoError(err)

	s.Run("should return 0", func() {
		_, actualError := s.repository.GetGrantsTotalCount(context.Background(), domain.ListGrantsFilter{})

		s.Nil(actualError)
	})

	s.Run("Should always total count on any size and any offset on success", func() {
		testCases := []struct {
			filters domain.ListGrantsFilter
		}{
			{
				filters: domain.ListGrantsFilter{
					Size:   1,
					Offset: 0,
				},
			},
			{
				filters: domain.ListGrantsFilter{
					Size:   1,
					Offset: 1,
				},
			},
		}
		for _, tc := range testCases {
			total, actualError := s.repository.GetGrantsTotalCount(context.Background(), tc.filters)
			s.NotNil(total)
			s.Nil(actualError)
		}
	})
}
func (s *GrantRepositoryTestSuite) TestListUserRoles() {
	s.Run("should return roles", func() {
		expectedRoles := []string{}

		actualResult, actualError := s.repository.ListUserRoles(context.Background(), "user")
		s.Equal(actualResult, expectedRoles)
		s.Nil(actualError)
	})
}

func (s *GrantRepositoryTestSuite) TestList() {
	expDate := time.Now()
	dummyGrants := []*domain.Grant{
		{
			Status:         domain.GrantStatusActive,
			AppealID:       s.dummyAppeal.ID,
			AccountID:      s.dummyAppeal.AccountID,
			AccountType:    s.dummyAppeal.AccountType,
			ResourceID:     s.dummyAppeal.ResourceID,
			Role:           s.dummyAppeal.Role,
			Permissions:    s.dummyAppeal.Permissions,
			CreatedBy:      s.dummyAppeal.CreatedBy,
			ExpirationDate: &expDate,
			IsPermanent:    true,
			Source:         domain.GrantSourceImport,
		},
	}
	err := s.repository.BulkInsert(context.Background(), dummyGrants)
	s.Require().NoError(err)

	s.Run("should return list of grant on success", func() {
		expectedGrant := &domain.Grant{}
		*expectedGrant = *dummyGrants[0]
		expectedGrant.Resource = s.dummyResource
		expectedGrant.Appeal = s.dummyAppeal

		trueBool := true
		grants, err := s.repository.List(context.Background(), domain.ListGrantsFilter{
			Statuses:                  []string{string(domain.GrantStatusActive)},
			AccountIDs:                []string{s.dummyAppeal.AccountID},
			AccountTypes:              []string{s.dummyAppeal.AccountType},
			ResourceIDs:               []string{s.dummyAppeal.ResourceID},
			Roles:                     []string{s.dummyAppeal.Role},
			Permissions:               s.dummyAppeal.Permissions,
			ProviderTypes:             []string{s.dummyResource.ProviderType},
			ProviderURNs:              []string{s.dummyResource.ProviderURN},
			ResourceTypes:             []string{s.dummyResource.Type},
			ResourceURNs:              []string{s.dummyResource.URN},
			CreatedBy:                 s.dummyAppeal.CreatedBy,
			OrderBy:                   []string{"status"},
			ExpirationDateLessThan:    time.Now(),
			ExpirationDateGreaterThan: time.Now().Add(-24 * time.Hour),
			IsPermanent:               &trueBool,
		})

		s.NoError(err)
		s.Len(grants, 1)
		if diff := cmp.Diff(*expectedGrant, grants[0], cmpopts.EquateApproxTime(time.Microsecond)); diff != "" {
			s.T().Errorf("result not match, diff: %v", diff)
		}
	})

	s.Run("could return error if db returns an error", func() {
		grants, err := s.repository.List(context.Background(), domain.ListGrantsFilter{
			ResourceIDs: []string{"invalid uuid"},
		})

		s.Error(err)
		s.Nil(grants)
	})
	s.Run("Should return an array size and offset of n on success", func() {
		testCases := []struct {
			filters        domain.ListGrantsFilter
			expectedArgs   []driver.Value
			expectedResult []*domain.Grant
		}{
			{
				filters: domain.ListGrantsFilter{
					Size:   1,
					Offset: 0,
				},
				expectedResult: []*domain.Grant{dummyGrants[0]},
			},
			{
				filters: domain.ListGrantsFilter{
					Offset: 1,
				},
				expectedResult: []*domain.Grant{dummyGrants[0]},
			},
		}
		for _, tc := range testCases {
			_, actualError := s.repository.List(context.Background(), tc.filters)
			s.Nil(actualError)
		}
	})

	s.Run("Should return an array that matches q", func() {
		grants, err := s.repository.List(context.Background(), domain.ListGrantsFilter{
			Q: "123",
		})

		s.NoError(err)
		s.Len(grants, 0)
	})
	s.Run("Should return an array of grants that matches account type", func() {
		grants, err := s.repository.List(context.Background(), domain.ListGrantsFilter{
			AccountTypes: []string{"x-account-type"},
		})
		s.NoError(err)
		s.Len(grants, 0)
	})

	s.Run("should filter grants by group_id and group_type", func() {
		ctx := context.Background()
		testGroupID := "test-group-id"

		groupAppeal := &domain.Appeal{
			ResourceID:    s.dummyResource.ID,
			PolicyID:      s.dummyPolicy.ID,
			PolicyVersion: s.dummyPolicy.Version,
			AccountID:     "groupuser@example.com",
			AccountType:   domain.DefaultAppealAccountType,
			Role:          "test-role",
			Status:        domain.AppealStatusApproved,
			Permissions:   []string{"test-permission"},
			CreatedBy:     "groupuser@example.com",
			GroupID:       testGroupID,
			GroupType:     "test-group-type",
		}

		appealRepository := postgres.NewAppealRepository(s.store.DB())
		err := appealRepository.BulkUpsert(ctx, []*domain.Appeal{groupAppeal})
		s.Require().NoError(err)

		expDate := time.Now()
		groupGrant := &domain.Grant{
			Status:         domain.GrantStatusActive,
			AppealID:       groupAppeal.ID,
			AccountID:      groupAppeal.AccountID,
			AccountType:    groupAppeal.AccountType,
			GroupID:        groupAppeal.GroupID,
			GroupType:      groupAppeal.GroupType,
			ResourceID:     groupAppeal.ResourceID,
			Role:           groupAppeal.Role,
			Permissions:    groupAppeal.Permissions,
			CreatedBy:      groupAppeal.CreatedBy,
			ExpirationDate: &expDate,
			Source:         domain.GrantSourceImport,
		}

		err = s.repository.BulkInsert(ctx, []*domain.Grant{groupGrant})
		s.Require().NoError(err)

		testCases := []struct {
			name        string
			filters     domain.ListGrantsFilter
			expectCount int
		}{
			{
				name: "filter by group_id",
				filters: domain.ListGrantsFilter{
					GroupIDs: []string{testGroupID},
				},
				expectCount: 1,
			},
			{
				name: "filter by group_type",
				filters: domain.ListGrantsFilter{
					GroupTypes: []string{"test-group-type"},
				},
				expectCount: 1,
			},
			{
				name: "filter by both group_id and group_type",
				filters: domain.ListGrantsFilter{
					GroupIDs:   []string{testGroupID},
					GroupTypes: []string{"test-group-type"},
				},
				expectCount: 1,
			},
			{
				name: "filter by non-existent group_id",
				filters: domain.ListGrantsFilter{
					GroupIDs: []string{"non-existent-group-id"},
				},
				expectCount: 0,
			},
		}

		for _, tc := range testCases {
			s.Run(tc.name, func() {
				grants, err := s.repository.List(ctx, tc.filters)
				s.NoError(err)
				s.Len(grants, tc.expectCount)

				if tc.expectCount > 0 {
					s.Equal(groupGrant.AppealID, grants[0].AppealID)
					s.Equal(testGroupID, grants[0].Appeal.GroupID)
					s.Equal("test-group-type", grants[0].Appeal.GroupType)
				}
			})
		}
	})
	s.Run("Should check accessing resource table", func() {
		grants, err := s.repository.List(context.Background(), domain.ListGrantsFilter{
			ProviderTypes: []string{"x"},
			ProviderURNs:  []string{"x"},
		})
		s.NoError(err)
		s.Len(grants, 0)
	})

	s.Run("should handle WithApprovals filter", func() {
		ctx := context.Background()

		// Create approvers
		approver1 := &domain.Approver{
			ID:       uuid.NewString(),
			AppealID: s.dummyAppeal.ID,
			Email:    "approver1@example.com",
		}
		approver2 := &domain.Approver{
			ID:       uuid.NewString(),
			AppealID: s.dummyAppeal.ID,
			Email:    "approver2@example.com",
		}

		// Create approvals with approvers
		approval1 := &domain.Approval{
			ID:        uuid.NewString(),
			Name:      "approval-step-1",
			AppealID:  s.dummyAppeal.ID,
			Status:    domain.ApprovalStatusApproved,
			Index:     0,
			Approvers: []string{"approver1@example.com"},
		}
		approval2 := &domain.Approval{
			ID:        uuid.NewString(),
			Name:      "approval-step-2",
			AppealID:  s.dummyAppeal.ID,
			Status:    domain.ApprovalStatusPending,
			Index:     1,
			Approvers: []string{"approver2@example.com"},
		}

		// Insert approvals
		approvalRepository := postgres.NewApprovalRepository(s.store.DB())
		err := approvalRepository.BulkInsert(ctx, []*domain.Approval{approval1, approval2})
		s.Require().NoError(err)

		// Test with WithApprovals = true
		grants, err := s.repository.List(ctx, domain.ListGrantsFilter{
			WithApprovals: true,
		})

		s.NoError(err)
		s.Len(grants, 1)

		// Verify appeal is loaded
		s.NotNil(grants[0].Appeal)
		s.Equal(s.dummyAppeal.ID, grants[0].Appeal.ID)

		// Verify approvals are loaded and ordered by index
		s.NotNil(grants[0].Appeal.Approvals)
		s.Len(grants[0].Appeal.Approvals, 2)
		s.Equal(approval1.ID, grants[0].Appeal.Approvals[0].ID)
		s.Equal(0, grants[0].Appeal.Approvals[0].Index)
		s.Equal(approval2.ID, grants[0].Appeal.Approvals[1].ID)
		s.Equal(1, grants[0].Appeal.Approvals[1].Index)

		// Verify approvers are loaded
		s.NotNil(grants[0].Appeal.Approvals[0].Approvers)
		s.Len(grants[0].Appeal.Approvals[0].Approvers, 1)
		s.Equal(approver1.Email, grants[0].Appeal.Approvals[0].Approvers[0])

		s.NotNil(grants[0].Appeal.Approvals[1].Approvers)
		s.Len(grants[0].Appeal.Approvals[1].Approvers, 1)
		s.Equal(approver2.Email, grants[0].Appeal.Approvals[1].Approvers[0])

		// Test with WithApprovals = false
		grants, err = s.repository.List(ctx, domain.ListGrantsFilter{
			WithApprovals: false,
		})

		s.NoError(err)
		s.Len(grants, 1)

		// Verify appeal is loaded but approvals are not
		s.NotNil(grants[0].Appeal)
		s.Equal(s.dummyAppeal.ID, grants[0].Appeal.ID)
		s.Empty(grants[0].Appeal.Approvals)

		// Test when WithApprovals is not specified (default behavior)
		grants, err = s.repository.List(ctx, domain.ListGrantsFilter{})

		s.NoError(err)
		s.Len(grants, 1)

		// Verify appeal is loaded but approvals are not
		s.NotNil(grants[0].Appeal)
		s.Equal(s.dummyAppeal.ID, grants[0].Appeal.ID)
		s.Empty(grants[0].Appeal.Approvals)
	})
}
func (s *GrantRepositoryTestSuite) TestGetByID() {
	dummyGrants := []*domain.Grant{
		{
			Status:      domain.GrantStatusActive,
			AppealID:    s.dummyAppeal.ID,
			AccountID:   s.dummyAppeal.AccountID,
			AccountType: s.dummyAppeal.AccountType,
			ResourceID:  s.dummyAppeal.ResourceID,
			Role:        s.dummyAppeal.Role,
			Permissions: s.dummyAppeal.Permissions,
			CreatedBy:   s.dummyAppeal.CreatedBy,
			Source:      domain.GrantSourceImport,
		},
	}
	err := s.repository.BulkInsert(context.Background(), dummyGrants)
	s.Require().NoError(err)

	s.Run("should return grant details on success", func() {
		expectedID := dummyGrants[0].ID
		expectedGrant := &domain.Grant{}
		*expectedGrant = *dummyGrants[0]
		expectedGrant.Resource = s.dummyResource
		expectedGrant.Appeal = s.dummyAppeal

		grant, err := s.repository.GetByID(context.Background(), expectedID)

		s.NoError(err)
		if diff := cmp.Diff(expectedGrant, grant, cmpopts.EquateApproxTime(time.Microsecond)); diff != "" {
			s.T().Errorf("result not match, diff: %v", diff)
		}
	})

	s.Run("should return not found error if record not found", func() {
		newID := uuid.NewString()
		actualGrant, err := s.repository.GetByID(context.Background(), newID)

		s.ErrorIs(err, grant.ErrGrantNotFound)
		s.Nil(actualGrant)
	})
}

func (s *GrantRepositoryTestSuite) TestUpdate() {
	dummyGrants := []*domain.Grant{
		{
			Status:      domain.GrantStatusActive,
			AppealID:    s.dummyAppeal.ID,
			AccountID:   s.dummyAppeal.AccountID,
			AccountType: s.dummyAppeal.AccountType,
			ResourceID:  s.dummyAppeal.ResourceID,
			Role:        s.dummyAppeal.Role,
			Permissions: s.dummyAppeal.Permissions,
			CreatedBy:   s.dummyAppeal.CreatedBy,
		},
	}
	err := s.repository.BulkInsert(context.Background(), dummyGrants)
	s.Require().NoError(err)

	s.Run("should return nil error on success", func() {
		expectedID := dummyGrants[0].ID
		payload := &domain.Grant{
			ID:     expectedID,
			Status: domain.GrantStatusInactive,
		}

		ctx := context.Background()
		err := s.repository.Update(ctx, payload)
		s.NoError(err)

		updatedGrant, err := s.repository.GetByID(ctx, expectedID)
		s.Require().NoError(err)

		s.Equal(payload.Status, updatedGrant.Status)
		s.Greater(updatedGrant.UpdatedAt, dummyGrants[0].UpdatedAt)
	})

	s.Run("should return error if id param is empty", func() {
		payload := &domain.Grant{
			ID:     "",
			Status: domain.GrantStatusInactive,
		}

		err := s.repository.Update(context.Background(), payload)

		s.ErrorIs(err, grant.ErrEmptyIDParam)
	})

	s.Run("should return error if db execution returns an error", func() {
		payload := &domain.Grant{
			ID:     "invalid-uuid",
			Status: domain.GrantStatusInactive,
		}

		err := s.repository.Update(context.Background(), payload)

		s.Error(err)
	})
}
