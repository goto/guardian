package grant_test

import (
	"context"
	"errors"
	"time"

	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/mock"
)

func (s *ServiceTestSuite) TestRevokeRestoresOriginalRecordOnProviderFailure() {
	for _, scenario := range []string{"provider failure", "cancelled request", "rollback failure"} {
		s.Run(scenario, func() {
			s.setup()
			oldTime := time.Now().Add(-time.Hour)
			original := domain.Grant{ID: "test-grant", Status: domain.GrantStatusActive, RevokedBy: "old-actor", RevokeReason: "old-reason", RevokedAt: &oldTime, Resource: &domain.Resource{ProviderType: domain.ProviderTypeMaxCompute}}
			fixture := original
			providerErr := errors.New("MaxCompute revoke unconfirmed")
			rollbackErr := errors.New("database unavailable")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s.mockRepository.EXPECT().GetByID(mock.Anything, original.ID).Return(&fixture, nil).Once()
			calls := 0
			s.mockRepository.EXPECT().Update(mock.Anything, mock.Anything).RunAndReturn(func(updateCtx context.Context, g *domain.Grant) error {
				calls++
				if calls == 1 {
					s.Equal(domain.GrantStatusInactive, g.Status)
					s.Equal("new-reason", g.RevokeReason)
					return nil
				}
				s.Equal(original, *g, "rollback must restore the complete original record")
				s.NoError(updateCtx.Err(), "rollback survives request cancellation")
				deadline, ok := updateCtx.Deadline()
				s.True(ok)
				s.LessOrEqual(time.Until(deadline), 5*time.Second)
				if scenario == "rollback failure" {
					return rollbackErr
				}
				return nil
			}).Twice()
			s.mockProviderService.EXPECT().RevokeAccess(mock.Anything, mock.Anything).RunAndReturn(func(context.Context, domain.Grant) error {
				if scenario == "cancelled request" {
					cancel()
				}
				return providerErr
			}).Once()
			result, err := s.service.Revoke(ctx, original.ID, "new-actor", "new-reason")
			s.Nil(result)
			s.ErrorIs(err, providerErr)
			if scenario == "rollback failure" {
				s.ErrorIs(err, rollbackErr)
			}
			s.mockRepository.AssertExpectations(s.T())
			s.mockProviderService.AssertExpectations(s.T())
			s.mockNotifier.AssertNotCalled(s.T(), "Notify", mock.Anything, mock.Anything)
			s.mockAuditLogger.AssertNotCalled(s.T(), "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}
