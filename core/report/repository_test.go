package report_test

import (
	"context"
	"testing"

	"github.com/goto/guardian/core/report"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/internal/store/postgres"
	"github.com/goto/guardian/pkg/log"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/suite"
)

type RepositoryTestSuite struct {
	suite.Suite
	store    *postgres.Store
	pool     *dockertest.Pool
	resource *dockertest.Resource

	repository         *report.Repository
	approvalRepository *postgres.ApprovalRepository
	appealRepository   *postgres.AppealRepository

	dummyProvider *domain.Provider
	dummyPolicy   *domain.Policy
	dummyResource *domain.Resource
	dummyAppeal   *domain.Appeal
	dummyApproval *domain.Approval
	dummyApprover *domain.Approver
}

func TestRepository(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	suite.Run(t, new(RepositoryTestSuite))
}

func (r *RepositoryTestSuite) SetupSuite() {
	var err error
	logger := log.NewCtxLogger("debug", []string{"test"})
	r.store, r.pool, r.resource, err = postgres.NewTestStore(logger)
	if err != nil {
		r.T().Fatal(err)
	}

	r.repository = report.NewRepository(r.store.DB())

	ctx := context.Background()

	r.dummyPolicy = &domain.Policy{
		ID:      "policy_test",
		Version: 1,
	}
	policyRepository := postgres.NewPolicyRepository(r.store.DB())
	err = policyRepository.Create(ctx, r.dummyPolicy)
	r.Require().NoError(err)

	r.dummyProvider = &domain.Provider{
		Type: "provider_test",
		URN:  "provider_urn_test",
		Config: &domain.ProviderConfig{
			Resources: []*domain.ResourceConfig{
				{
					Type: "resource_type_test",
					Policy: &domain.PolicyConfig{
						ID:      r.dummyPolicy.ID,
						Version: int(r.dummyPolicy.Version),
					},
				},
			},
		},
	}
	providerRepository := postgres.NewProviderRepository(r.store.DB())
	err = providerRepository.Create(ctx, r.dummyProvider)
	r.Require().NoError(err)

	r.dummyResource = &domain.Resource{
		ProviderType: r.dummyProvider.Type,
		ProviderURN:  r.dummyProvider.URN,
		Type:         "resource_type_test",
		URN:          "resource_urn_test",
		Name:         "resource_name_test",
	}
	resourceRepository := postgres.NewResourceRepository(r.store.DB())
	err = resourceRepository.BulkUpsert(ctx, []*domain.Resource{r.dummyResource})
	r.Require().NoError(err)

	r.dummyAppeal = &domain.Appeal{
		ResourceID:    r.dummyResource.ID,
		PolicyID:      r.dummyPolicy.ID,
		PolicyVersion: r.dummyPolicy.Version,
		AccountID:     "user@example.com",
		AccountType:   domain.DefaultAppealAccountType,
		Role:          "role_test",
		Permissions:   []string{"permission_test"},
		CreatedBy:     "user@example.com",
		Status:        "pending",
	}
	r.appealRepository = postgres.NewAppealRepository(r.store.DB())
	err = r.appealRepository.BulkUpsert(ctx, []*domain.Appeal{r.dummyAppeal})
	r.Require().NoError(err)

	r.dummyApproval = &domain.Approval{
		Name:     "Approval",
		AppealID: r.dummyAppeal.ID,
		Status:   "pending",
	}
	r.approvalRepository = postgres.NewApprovalRepository(r.store.DB())
	err = r.approvalRepository.BulkInsert(ctx, []*domain.Approval{r.dummyApproval})
	r.Require().NoError(err)

	r.dummyApprover = &domain.Approver{
		ApprovalID: r.dummyApproval.ID,
		AppealID:   r.dummyAppeal.ID,
		Email:      "approver@example.com",
	}
	r.approvalRepository = postgres.NewApprovalRepository(r.store.DB())
	err = r.approvalRepository.AddApprover(ctx, r.dummyApprover)
	r.Require().NoError(err)
}

func (s *RepositoryTestSuite) TearDownSuite() {
	// Clean tests
	db, err := s.store.DB().DB()
	if err != nil {
		s.T().Fatal(err)
	}
	err = db.Close()
	if err != nil {
		s.T().Fatal(err)
	}

	err = postgres.PurgeTestDocker(s.pool, s.resource)
	if err != nil {
		s.T().Fatal(err)
	}
}

func (s *RepositoryTestSuite) TestGetPendingApprovalsList() {
	dummyReports := []report.PendingApprovalsReport{
		{
			Approver:  "approver@gojek.com",
			Requestor: "user@gojek.com",
			Status:    "pending",
		},
	}
	s.Run("should return nil and error if got error from repository", func() {
		reports, err := s.repository.GetPendingApprovalsList(context.Background(), &report.PendingApprovalsReportFilter{
			AppealStatuses:   []string{"pending"},
			ApprovalStatuses: []string{"pending"},
		})

		s.NoError(err)
		s.Len(reports, 1)
		s.Equal(dummyReports[0].Approver, dummyReports[0].Approver)
	})
}
