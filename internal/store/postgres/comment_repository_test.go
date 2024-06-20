package postgres_test

import (
	"context"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/internal/store/postgres"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/pkg/postgrestest"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/suite"
)

type CommentRepositorySuite struct {
	suite.Suite
	store            *postgres.Store
	pool             *dockertest.Pool
	resource         *dockertest.Resource
	repository       *postgres.CommentRepository
	appealRepository *postgres.AppealRepository

	dummyProvider *domain.Provider
	dummyPolicy   *domain.Policy
	dummyResource *domain.Resource
	dummyAppeal   *domain.Appeal
}

func TestCommentRepository(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	suite.Run(t, new(CommentRepositorySuite))
}

func (s *CommentRepositorySuite) SetupSuite() {
	var err error
	logger := log.NewCtxLogger("debug", []string{"test"})
	s.store, s.pool, s.resource, err = postgrestest.NewTestStore(logger)
	if err != nil {
		s.T().Fatal(err)
	}

	s.repository = postgres.NewCommentRepository(s.store.DB())

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
		Permissions:   []string{"test-permission"},
	}

	s.appealRepository = postgres.NewAppealRepository(s.store.DB())
	err = s.appealRepository.BulkUpsert(ctx, []*domain.Appeal{s.dummyAppeal})
	s.Require().NoError(err)
}

func (s *CommentRepositorySuite) TearDownSuite() {
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

func (s *CommentRepositorySuite) TestCreateAndListComments() {
	ctx := context.Background()

	// create comments
	comments := []*domain.Comment{
		{
			ParentID:  s.dummyAppeal.ID,
			Body:      "comment_test_1",
			CreatedBy: "user_1",
		},
		{
			ParentID:  s.dummyAppeal.ID,
			Body:      "comment_test_2",
			CreatedBy: "user_2",
		},
	}
	for _, c := range comments {
		err := s.repository.Create(ctx, c)
		s.Require().NoError(err)
	}

	// list comments
	filter := domain.ListCommentsFilter{
		ParentID: s.dummyAppeal.ID,
		OrderBy:  []string{"created_by:desc"},
	}

	listedComments, err := s.repository.List(ctx, filter)
	s.Require().NoError(err)
	s.Require().Len(listedComments, 2)
}
