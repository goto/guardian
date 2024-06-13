package report_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/goto/guardian/core/report"
	"github.com/goto/guardian/internal/store"
	"github.com/goto/guardian/internal/store/postgres"
	"github.com/goto/guardian/pkg/log"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/suite"
)

var (
	storeConfig = store.Config{
		Host:     "localhost",
		User:     "test_user",
		Password: "test_pass",
		Name:     "test_db",
		SslMode:  "disable",
	}
)

type ServiceTestSuite struct {
	suite.Suite
	store   *postgres.Store
	service *report.Service
}

func TestService(t *testing.T) {
	suite.Run(t, new(ServiceTestSuite))
}

func (s *ServiceTestSuite) SetupTest() {
	var err error
	logger := log.NewCtxLogger("info", []string{"test"})
	store, pool, resource, err := newTestStore(logger)
	if err != nil {
		s.T().Fatal(err)
	}
	s.store = store
	s.T().Cleanup(func() {
		db, err := s.store.DB().DB()
		if err != nil {
			s.T().Fatal(err)
		}
		if err := db.Close(); err != nil {
			s.T().Fatal(err)
		}
		if err := purgeTestDocker(pool, resource); err != nil {
			s.T().Fatal(err)
		}
	})

	s.service = report.NewService(report.ServiceDeps{
		DB: s.store.DB(),
	})
}

func (s *ServiceTestSuite) TestGetPendingApprovalsList() {
	dummyReports := []report.Report{
		{
			ID:        "1",
			Approver:  "approver@gojek.com",
			Requestor: "requestor@gojek.com",
			Project:   "projectX",
			Resource:  "resourceY",
			Status:    "pending",
		},
	}
	s.Run("should return nil and error if got error from repository", func() {
		reports, err := s.service.GetPendingApprovalsList(context.Background(), report.ReportFilter{
			AppealStatuses:   []string{"pending"},
			ApprovalStatuses: []string{"pending"},
		})

		s.NoError(err)
		s.Len(reports, 1)
		s.Equal(dummyReports[0].ID, dummyReports[0].ID)
	})
}

func newTestStore(logger log.Logger) (*postgres.Store, *dockertest.Pool, *dockertest.Resource, error) {
	ctx := context.Background()
	opts := &dockertest.RunOptions{
		Repository: "postgres",
		Tag:        "13",
		Env: []string{
			"POSTGRES_PASSWORD=" + storeConfig.Password,
			"POSTGRES_USER=" + storeConfig.User,
			"POSTGRES_DB=" + storeConfig.Name,
		},
	}

	// uses a sensible default on windows (tcp/http) and linux/osx (socket)
	pool, err := dockertest.NewPool("")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not create dockertest pool: %w", err)
	}

	// pulls an image, creates a container based on it and runs it
	resource, err := pool.RunWithOptions(opts, func(config *docker.HostConfig) {
		// set AutoRemove to true so that stopped container goes away by itself
		config.AutoRemove = true
		config.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not start resource: %w", err)
	}

	storeConfig.Port = resource.GetPort("5432/tcp")

	// attach terminal logger to container if exists
	// for debugging purpose
	if logger.Level() == "debug" {
		logWaiter, err := pool.Client.AttachToContainerNonBlocking(docker.AttachToContainerOptions{
			Container:    resource.Container.ID,
			OutputStream: logger.Writer(),
			ErrorStream:  logger.Writer(),
			Stderr:       true,
			Stdout:       true,
			Stream:       true,
		})
		if err != nil {
			logger.Fatal(ctx, "could not connect to postgres container log output", "error", err)
		}
		defer func() {
			err = logWaiter.Close()
			if err != nil {
				logger.Fatal(ctx, "could not close container log", "error", err)
			}

			err = logWaiter.Wait()
			if err != nil {
				logger.Fatal(ctx, "could not wait for container log to close", "error", err)
			}
		}()
	}

	// Tell docker to hard kill the container in 120 seconds
	if err := resource.Expire(120); err != nil {
		return nil, nil, nil, err
	}

	// exponential backoff-retry, because the application in the container might not be ready to accept connections yet
	pool.MaxWait = 60 * time.Second

	var st *postgres.Store
	time.Sleep(5 * time.Second)
	if err = pool.Retry(func() error {
		st, err = postgres.NewStore(&storeConfig)
		if err != nil {
			return err
		}

		return nil
	}); err != nil {
		return nil, nil, nil, fmt.Errorf("could not connect to docker: %w", err)
	}

	err = setup(st)
	if err != nil {
		logger.Fatal(ctx, "failed to setup and migrate DB", "error", err)
	}
	return st, pool, resource, nil
}

func purgeTestDocker(pool *dockertest.Pool, resource *dockertest.Resource) error {
	if err := pool.Purge(resource); err != nil {
		return fmt.Errorf("could not purge resource: %w", err)
	}
	return nil
}

func setup(store *postgres.Store) error {
	var queries = []string{
		"DROP SCHEMA public CASCADE",
		"CREATE SCHEMA public",
	}
	for _, query := range queries {
		store.DB().Exec(query)
	}

	if err := store.Migrate(); err != nil {
		return err
	}

	return nil
}
