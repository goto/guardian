package alertmanager_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/plugins/notifiers/alertmanager"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

// mockSender is a testify mock for alertmanager.PDSender.
type mockSender struct {
	mock.Mock
}

func (m *mockSender) Send(ctx context.Context, event alertmanager.Event, logger log.Logger) error {
	args := m.Called(ctx, event, logger)
	return args.Error(0)
}

type AlertManagerTestSuite struct {
	suite.Suite
	pd  *mockSender
	svc *alertmanager.AlertManager
}

func TestAlertManager(t *testing.T) {
	suite.Run(t, new(AlertManagerTestSuite))
}

func (s *AlertManagerTestSuite) setupManager() {
	s.pd = new(mockSender)
	s.svc = alertmanager.New(s.pd, log.NewNoop())
}

func (s *AlertManagerTestSuite) TestNotifyDriftCheck() {
	ctx := context.Background()
	adminTeam := "admin-team"

	resource1 := &domain.Resource{
		URN:          "mc://project1/table1",
		GlobalURN:    "urn:maxcompute:123456:table:project1.default.table1",
		Name:         "table1",
		ProviderType: "maxcompute",
	}

	s.Run("sends warning event when all grants are successfully recreated", func() {
		s.setupManager()

		issues := []domain.GrantDriftIssue{
			{
				AccountID: "user-1",
				Grant:     &domain.Grant{ID: "g-1", AccountType: "ram_user", Role: "reader", Resource: resource1},
			},
			{
				AccountID: "user-2",
				Grant:     &domain.Grant{ID: "g-2", AccountType: "ram_user", Role: "reader", Resource: resource1},
			},
		}

		s.pd.On("Send", ctx, mock.MatchedBy(func(e alertmanager.Event) bool {
			return e.Team == adminTeam &&
				e.Title == alertmanager.GrantDriftCheckEvent &&
				e.Severity == "warning" &&
				strings.Contains(e.Summary, "2 drifted grant(s)") &&
				strings.Contains(e.Summary, "2 recreated") &&
				strings.Contains(e.Summary, "0 failed")
		}), mock.Anything).Return(nil).Once()

		err := s.svc.NotifyDriftCheck(ctx, alertmanager.NotifyDriftCheckRequest{AdminTeam: adminTeam, Issues: issues, OnSuccessSeverity: "warning"})

		s.Nil(err)
		s.pd.AssertExpectations(s.T())
	})

	s.Run("sends critical event when at least one remediation failed", func() {
		s.setupManager()

		issues := []domain.GrantDriftIssue{
			{
				AccountID: "user-1",
				Grant:     &domain.Grant{ID: "g-1", AccountType: "ram_user"},
			},
			{
				AccountID:        "user-2",
				Grant:            &domain.Grant{ID: "g-2", AccountType: "ram_user"},
				RemediationError: "provider unavailable",
			},
		}

		s.pd.On("Send", ctx, mock.MatchedBy(func(e alertmanager.Event) bool {
			return strings.Contains(e.Summary, "1 failed") &&
				strings.Contains(e.Summary, "2 critical bot(s)") &&
				e.Title == alertmanager.GrantDriftCheckEvent
		}), mock.Anything).Return(nil).Once()

		err := s.svc.NotifyDriftCheck(ctx, alertmanager.NotifyDriftCheckRequest{AdminTeam: adminTeam, Issues: issues})

		s.Nil(err)
		s.pd.AssertExpectations(s.T())
	})

	s.Run("marks failed remediation in details with error message", func() {
		s.setupManager()

		remediationErr := "access denied"
		issues := []domain.GrantDriftIssue{
			{
				AccountID:        "user-1",
				Grant:            &domain.Grant{ID: "g-1"},
				RemediationError: remediationErr,
			},
		}

		s.pd.On("Send", ctx, mock.MatchedBy(func(e alertmanager.Event) bool {
			accounts, ok := e.Data["accounts"].([]map[string]interface{})
			if !ok || len(accounts) != 1 {
				return false
			}
			grants, ok := accounts[0]["grants"].([]map[string]interface{})
			return ok && len(grants) == 1 &&
				grants[0]["remediation_status"] == "failed" &&
				grants[0]["remediation_error"] == remediationErr &&
				e.Title == alertmanager.GrantDriftCheckEvent
		}), mock.Anything).Return(nil).Once()

		err := s.svc.NotifyDriftCheck(ctx, alertmanager.NotifyDriftCheckRequest{AdminTeam: adminTeam, Issues: issues})

		s.Nil(err)
		s.pd.AssertExpectations(s.T())
	})

	s.Run("includes resource info in grant details when resource is set", func() {
		s.setupManager()

		issues := []domain.GrantDriftIssue{
			{
				AccountID: "user-1",
				Grant:     &domain.Grant{ID: "g-1", Resource: resource1},
			},
		}

		s.pd.On("Send", ctx, mock.MatchedBy(func(e alertmanager.Event) bool {
			accounts, ok := e.Data["accounts"].([]map[string]interface{})
			if !ok || len(accounts) != 1 {
				return false
			}
			grants, ok := accounts[0]["grants"].([]map[string]interface{})
			if !ok || len(grants) != 1 {
				return false
			}
			resourceStr, ok := grants[0]["resource"].(string)
			return ok && resourceStr == resource1.URN &&
				e.Title == alertmanager.GrantDriftCheckEvent
		}), mock.Anything).Return(nil).Once()

		err := s.svc.NotifyDriftCheck(ctx, alertmanager.NotifyDriftCheckRequest{AdminTeam: adminTeam, Issues: issues})

		s.Nil(err)
		s.pd.AssertExpectations(s.T())
	})

	s.Run("returns error when PagerDuty send fails", func() {
		s.setupManager()

		pdErr := errors.New("pagerduty api error")
		issues := []domain.GrantDriftIssue{
			{AccountID: "user-1", Grant: &domain.Grant{ID: "g-1"}},
		}

		s.pd.On("Send", ctx, mock.Anything, mock.Anything).Return(pdErr).Once()

		err := s.svc.NotifyDriftCheck(ctx, alertmanager.NotifyDriftCheckRequest{AdminTeam: adminTeam, Issues: issues})

		s.ErrorIs(err, pdErr)
		s.pd.AssertExpectations(s.T())
	})

	s.Run("sends correct aggregate counts for mixed issue types", func() {
		s.setupManager()

		issues := []domain.GrantDriftIssue{
			{AccountID: "u-1", Grant: &domain.Grant{ID: "g-1"}},
			{AccountID: "u-2", Grant: &domain.Grant{ID: "g-2"}, RemediationError: "err"},
			{AccountID: "u-3", Grant: &domain.Grant{ID: "g-3"}},
		}

		s.pd.On("Send", ctx, mock.MatchedBy(func(e alertmanager.Event) bool {
			return strings.Contains(e.Summary, "3 drifted grant(s)") &&
				strings.Contains(e.Summary, "3 critical bot(s)") &&
				strings.Contains(e.Summary, "2 recreated") &&
				strings.Contains(e.Summary, "1 failed") &&
				e.Title == alertmanager.GrantDriftCheckEvent
		}), mock.Anything).Return(nil).Once()

		err := s.svc.NotifyDriftCheck(ctx, alertmanager.NotifyDriftCheckRequest{AdminTeam: adminTeam, Issues: issues})

		s.Nil(err)
		s.pd.AssertExpectations(s.T())
	})
}
