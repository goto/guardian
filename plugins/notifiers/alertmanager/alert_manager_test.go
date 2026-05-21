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

// mockPDSender is a testify mock for alertmanager.PDSender.
type mockPDSender struct {
	mock.Mock
}

func (m *mockPDSender) Send(ctx context.Context, event alertmanager.Event) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

type AlertManagerTestSuite struct {
	suite.Suite
	pd  *mockPDSender
	svc *alertmanager.AlertManager
}

func TestAlertManager(t *testing.T) {
	suite.Run(t, new(AlertManagerTestSuite))
}

func (s *AlertManagerTestSuite) setupManager() {
	s.pd = new(mockPDSender)
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
			return e.RoutingKey == adminTeam &&
				e.Severity == "warning" &&
				e.EventAction == "trigger" &&
				strings.Contains(e.Summary, "2 drifted grant(s)") &&
				strings.Contains(e.Summary, "2 recreated") &&
				strings.Contains(e.Summary, "0 failed")
		})).Return(nil).Once()

		errs := s.svc.NotifyDriftCheck(ctx, adminTeam, issues)

		s.Nil(errs)
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
				strings.Contains(e.Summary, "2 critical bot(s)")
		})).Return(nil).Once()

		errs := s.svc.NotifyDriftCheck(ctx, adminTeam, issues)

		s.Nil(errs)
		s.pd.AssertExpectations(s.T())
	})

	s.Run("marks not_applicable issues in details and counts them correctly", func() {
		s.setupManager()

		issues := []domain.GrantDriftIssue{
			{
				AccountID:                "user-1",
				Grant:                    &domain.Grant{ID: "g-1"},
				RemediationNotApplicable: true,
			},
		}

		s.pd.On("Send", ctx, mock.MatchedBy(func(e alertmanager.Event) bool {
			if !strings.Contains(e.Summary, "1 not_applicable") {
				return false
			}
			accounts, ok := e.CustomDetails["accounts"].([]map[string]interface{})
			if !ok || len(accounts) != 1 {
				return false
			}
			grants, ok := accounts[0]["grants"].([]map[string]interface{})
			return ok && len(grants) == 1 && grants[0]["remediation_status"] == "not_applicable"
		})).Return(nil).Once()

		errs := s.svc.NotifyDriftCheck(ctx, adminTeam, issues)

		s.Nil(errs)
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
			accounts, ok := e.CustomDetails["accounts"].([]map[string]interface{})
			if !ok || len(accounts) != 1 {
				return false
			}
			grants, ok := accounts[0]["grants"].([]map[string]interface{})
			return ok && len(grants) == 1 &&
				grants[0]["remediation_status"] == "failed" &&
				grants[0]["remediation_error"] == remediationErr
		})).Return(nil).Once()

		errs := s.svc.NotifyDriftCheck(ctx, adminTeam, issues)

		s.Nil(errs)
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
			accounts, ok := e.CustomDetails["accounts"].([]map[string]interface{})
			if !ok || len(accounts) != 1 {
				return false
			}
			grants, ok := accounts[0]["grants"].([]map[string]interface{})
			if !ok || len(grants) != 1 {
				return false
			}
			resourceStr, ok := grants[0]["resource"].(string)
			return ok && resourceStr == resource1.GlobalURN
		})).Return(nil).Once()

		errs := s.svc.NotifyDriftCheck(ctx, adminTeam, issues)

		s.Nil(errs)
		s.pd.AssertExpectations(s.T())
	})

	s.Run("returns error when PagerDuty send fails", func() {
		s.setupManager()

		pdErr := errors.New("pagerduty api error")
		issues := []domain.GrantDriftIssue{
			{AccountID: "user-1", Grant: &domain.Grant{ID: "g-1"}},
		}

		s.pd.On("Send", ctx, mock.Anything).Return(pdErr).Once()

		errs := s.svc.NotifyDriftCheck(ctx, adminTeam, issues)

		s.Require().Len(errs, 1)
		s.ErrorIs(errs[0], pdErr)
		s.pd.AssertExpectations(s.T())
	})

	s.Run("sends correct aggregate counts for mixed issue types", func() {
		s.setupManager()

		issues := []domain.GrantDriftIssue{
			{AccountID: "u-1", Grant: &domain.Grant{ID: "g-1"}},
			{AccountID: "u-2", Grant: &domain.Grant{ID: "g-2"}, RemediationError: "err"},
			{AccountID: "u-3", Grant: &domain.Grant{ID: "g-3"}, RemediationNotApplicable: true},
			{AccountID: "u-4", Grant: &domain.Grant{ID: "g-4"}},
		}

		s.pd.On("Send", ctx, mock.MatchedBy(func(e alertmanager.Event) bool {
			return strings.Contains(e.Summary, "4 drifted grant(s)") &&
				strings.Contains(e.Summary, "4 critical bot(s)") &&
				strings.Contains(e.Summary, "2 recreated") &&
				strings.Contains(e.Summary, "1 failed") &&
				strings.Contains(e.Summary, "1 not_applicable")
		})).Return(nil).Once()

		errs := s.svc.NotifyDriftCheck(ctx, adminTeam, issues)

		s.Nil(errs)
		s.pd.AssertExpectations(s.T())
	})
}
