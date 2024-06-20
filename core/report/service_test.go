package report_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/goto/guardian/core/report"
	reportmocks "github.com/goto/guardian/core/report/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type ServiceTestSuite struct {
	suite.Suite
	mockRepository *reportmocks.Repository

	service *report.Service
}

func TestService(t *testing.T) {
	suite.Run(t, new(ServiceTestSuite))
}

func (s *ServiceTestSuite) SetupTest() {
	s.mockRepository = new(reportmocks.Repository)

	s.service = report.NewService(report.ServiceDeps{
		s.mockRepository,
	})
}

func (s *ServiceTestSuite) TestGetPendingApprovalsList() {
	s.Run("should return error if got error from repository", func() {
		expectedError := errors.New("repository error")
		s.mockRepository.EXPECT().
			GetPendingApprovalsList(mock.MatchedBy(func(ctx context.Context) bool { return true }), mock.Anything).
			Return(nil, expectedError).Once()

		actualApprovals, actualError := s.service.GetPendingApprovalsList(context.Background(), &report.PendingApprovalsReportFilter{})

		s.Nil(actualApprovals)
		s.EqualError(actualError, expectedError.Error())
	})

	s.Run("should return approvals from repository", func() {
		expectedApprovals := []*report.PendingApprovalsReport{
			{
				AppealID: uuid.New().String(),
			},
		}
		s.mockRepository.EXPECT().
			GetPendingApprovalsList(mock.MatchedBy(func(ctx context.Context) bool { return true }), mock.Anything).
			Return(expectedApprovals, nil).Once()

		actualApprovals, actualError := s.service.GetPendingApprovalsList(context.Background(), &report.PendingApprovalsReportFilter{})

		s.Equal(expectedApprovals, actualApprovals)
		s.NoError(actualError)
	})
}
