package grant_test

import (
	"context"
	"errors"
	"fmt"
	"time"

	guardianv1beta1 "github.com/goto/guardian/api/proto/gotocompany/guardian/v1beta1"
	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/mock"
)

func (s *ServiceTestSuite) TestSmartInactiveFindsRenewalsRequestedByAnotherOwner() {
	s.setup()
	ctx := context.Background()
	oldEnd := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	filter := domain.ListGrantsFilter{Owner: "requestor@example.test", CreatedBy: "requestor@example.test",
		Statuses: []string{"inactive"}, EndTime: oldEnd, AppealDurations: []string{"90d"},
		Offset: 20, Size: 10, UserInactiveGrantPolicy: guardianv1beta1.ListUserGrantsRequest_INACTIVE_GRANT_POLICY_SMART}
	inactive := []domain.Grant{
		{ID: "old-self", ResourceID: "package", AccountID: "Person@example.test", Role: "admin", Owner: filter.Owner},
		{ID: "old-on-behalf", ResourceID: "package", AccountID: "other@example.test", Role: "member", Owner: filter.Owner},
		{ID: "actually-expired", ResourceID: "package", AccountID: "expired@example.test", Role: "member", Owner: filter.Owner},
		{ID: "different-role", ResourceID: "package", AccountID: "person@example.test", Role: "member", Owner: filter.Owner},
	}
	s.mockRepository.EXPECT().List(mock.Anything, mock.MatchedBy(func(f domain.ListGrantsFilter) bool {
		return len(f.Statuses) == 1 && f.Statuses[0] == "inactive" && f.Owner == filter.Owner && f.CreatedBy == filter.CreatedBy && f.EndTime.Equal(oldEnd) && f.Size == 0 && f.Offset == 0
	})).Return(inactive, nil).Once()
	s.mockRepository.EXPECT().List(mock.Anything, mock.MatchedBy(func(f domain.ListGrantsFilter) bool {
		return len(f.Statuses) == 1 && f.Statuses[0] == "active" && f.Owner == "" && f.CreatedBy == "" && len(f.Owners) == 0 && f.EndTime.IsZero() && len(f.AppealDurations) == 0 && len(f.AccountIDs) == 3 && len(f.ResourceIDs) == 1 && f.ResourceIDs[0] == "package"
	})).Return([]domain.Grant{
		{ID: "new-self", ResourceID: "package", AccountID: "person@example.test", Role: "admin", Owner: "different-admin@example.test"},
		{ID: "new-on-behalf", ResourceID: "package", AccountID: "other@example.test", Role: "member", Owner: "different-admin@example.test"},
	}, nil).Once()
	ids, err := s.service.GenerateUserExcludedGrantIDsForSmartInactiveGrants(ctx, filter)
	s.NoError(err)
	s.ElementsMatch([]string{"old-self", "old-on-behalf"}, ids)
	s.mockRepository.AssertExpectations(s.T())
}

func (s *ServiceTestSuite) TestSmartInactiveEmptyHistoryDoesNotQueryAllActiveGrants() {
	s.setup()
	s.mockRepository.EXPECT().List(mock.Anything, mock.Anything).Return(nil, nil).Once()
	ids, err := s.service.GenerateUserExcludedGrantIDsForSmartInactiveGrants(context.Background(), domain.ListGrantsFilter{Owner: "user@example.test", UserInactiveGrantPolicy: guardianv1beta1.ListUserGrantsRequest_INACTIVE_GRANT_POLICY_SMART})
	s.NoError(err)
	s.Empty(ids)
	s.mockRepository.AssertExpectations(s.T())
}

func (s *ServiceTestSuite) TestSmartInactiveCounterpartLookupsAreBounded() {
	s.setup()
	inactive := make([]domain.Grant, 251)
	for i := range inactive {
		inactive[i] = domain.Grant{ID: fmt.Sprintf("old-%d", i), ResourceID: fmt.Sprintf("r-%d", i), AccountID: fmt.Sprintf("u-%d", i), Role: "reader"}
	}
	s.mockRepository.EXPECT().List(mock.Anything, mock.MatchedBy(func(f domain.ListGrantsFilter) bool { return len(f.Statuses) == 1 && f.Statuses[0] == "inactive" })).Return(inactive, nil).Once()
	for _, size := range []int{250, 1} {
		size := size
		s.mockRepository.EXPECT().List(mock.Anything, mock.MatchedBy(func(f domain.ListGrantsFilter) bool {
			return len(f.Statuses) == 1 && f.Statuses[0] == "active" && len(f.AccountIDs) == size && len(f.ResourceIDs) == size && f.Owner == ""
		})).Return(nil, nil).Once()
	}
	ids, err := s.service.GenerateUserExcludedGrantIDsForSmartInactiveGrants(context.Background(), domain.ListGrantsFilter{Owner: "user@example.test", UserInactiveGrantPolicy: guardianv1beta1.ListUserGrantsRequest_INACTIVE_GRANT_POLICY_SMART})
	s.NoError(err)
	s.Empty(ids)
	s.mockRepository.AssertExpectations(s.T())
}

func (s *ServiceTestSuite) TestSmartInactiveCounterpartFailureDoesNotHideHistory() {
	s.setup()
	s.mockRepository.EXPECT().List(mock.Anything, mock.MatchedBy(func(f domain.ListGrantsFilter) bool { return f.Statuses[0] == "inactive" })).Return([]domain.Grant{{ID: "old", ResourceID: "r", AccountID: "user", Role: "reader"}}, nil).Once()
	want := errors.New("synthetic database failure")
	s.mockRepository.EXPECT().List(mock.Anything, mock.MatchedBy(func(f domain.ListGrantsFilter) bool { return f.Statuses[0] == "active" })).Return(nil, want).Once()
	ids, err := s.service.GenerateUserExcludedGrantIDsForSmartInactiveGrants(context.Background(), domain.ListGrantsFilter{Owner: "user@example.test", UserInactiveGrantPolicy: guardianv1beta1.ListUserGrantsRequest_INACTIVE_GRANT_POLICY_SMART})
	s.ErrorIs(err, want)
	s.Nil(ids)
}
