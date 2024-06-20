package report_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/goto/guardian/core/report"
	reportmocks "github.com/goto/guardian/core/report/mocks"
	"github.com/goto/guardian/pkg/log"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type ServiceTestSuite struct {
	suite.Suite
	mockRepository *reportmocks.Repository
	mockNotifier   *reportmocks.Notifier

	service    *report.Service
	ctxMatcher interface{}
}

func TestService(t *testing.T) {
	suite.Run(t, new(ServiceTestSuite))
}

func (s *ServiceTestSuite) SetupTest() {
	logger := log.NewNoop()
	s.mockRepository = new(reportmocks.Repository)
	s.mockNotifier = new(reportmocks.Notifier)
	s.ctxMatcher = mock.MatchedBy(func(ctx context.Context) bool { return true })

	s.service = report.NewService(report.ServiceDeps{
		s.mockRepository,
		logger,
		s.mockNotifier,
	})
}

func (s *ServiceTestSuite) TestGetPendingApprovalsList() {
	s.Run("should return error if got error from repository", func() {
		expectedError := errors.New("repository error")
		s.mockRepository.EXPECT().
			GetPendingApprovalsList(mock.MatchedBy(func(ctx context.Context) bool { return true }), mock.Anything).
			Return(nil, expectedError).Once()

		actualApprovals, actualError := s.service.GetPendingApprovalsList(context.Background(), &report.GetPendingApprovalsListConfig{})

		s.Nil(actualApprovals)
		s.EqualError(actualError, expectedError.Error())
	})

	s.Run("should return approvals from repository", func() {
		expectedApprovals := []*report.PendingApproval{
			{
				Approver: "approver@example.com",
				Count:    2,
				Appeals: []report.PendingAppeal{
					{
						ID: "appeal01",
					},
					{
						ID: "appeal02",
					},
				},
			},
		}

		pendingApprovals := []*report.PendingApprovalModel{
			{
				AppealID:        "appeal01",
				Approver:        "approver@example.com",
				AppealCreatedAt: time.Now(),
			},
			{
				AppealID:        "appeal02",
				Approver:        "approver@example.com",
				AppealCreatedAt: time.Now(),
			},
		}

		s.mockRepository.EXPECT().
			GetPendingApprovalsList(mock.MatchedBy(func(ctx context.Context) bool { return true }), mock.Anything).
			Return(pendingApprovals, nil).Once()
		s.mockNotifier.EXPECT().
			Notify(s.ctxMatcher, mock.Anything).Return(nil).Once()

		actualApprovals, actualError := s.service.GetPendingApprovalsList(context.Background(), &report.GetPendingApprovalsListConfig{})

		s.Equal(expectedApprovals, actualApprovals)
		s.NoError(actualError)
	})
}
