package grant_test

import (
	"context"
	"errors"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/goto/guardian/core/grant"
	"github.com/goto/guardian/core/grant/mocks"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/plugins/notifiers/alertmanager"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type GrantDriftCheckTestSuite struct {
	suite.Suite
	mockRepo         *mocks.Repository
	mockProviderSvc  *mocks.ProviderService
	mockAuditLogger  *mocks.AuditLogger
	mockAlertManager *mocks.AlertManager
	service          *grant.Service
}

func TestGrantDriftCheck(t *testing.T) {
	suite.Run(t, new(GrantDriftCheckTestSuite))
}

func (s *GrantDriftCheckTestSuite) setupService() {
	s.mockRepo = new(mocks.Repository)
	s.mockProviderSvc = new(mocks.ProviderService)
	s.mockAuditLogger = new(mocks.AuditLogger)
	s.mockAlertManager = new(mocks.AlertManager)
	s.service = grant.NewService(grant.ServiceDeps{
		Repository:      s.mockRepo,
		Logger:          log.NewNoop(),
		Validator:       validator.New(),
		ProviderService: s.mockProviderSvc,
		AlertManager:    s.mockAlertManager,
		AuditLogger:     s.mockAuditLogger,
	})
}

func (s *GrantDriftCheckTestSuite) TestGrantDriftCheck() {
	const (
		botAccountID = "RAM$12345:12345"
		provType     = "maxcompute"
		provURN      = "mc://project1"
		adminTeam    = "admin-team"
		teamName     = "team-alpha"

		resourceID1  = "res-id-1"
		resourceID2  = "res-id-2"
		resourceURN1 = "res-urn-1"
		resourceURN2 = "res-urn-2"

		groupID   = "group-1"
		groupRole = "RAM$12345:role/group-1-role"

		grantID  = "grant-id-1"
		grantID2 = "grant-id-2"
	)

	resource1 := &domain.Resource{
		ID:           resourceID1,
		URN:          resourceURN1,
		Type:         "table",
		ProviderType: provType,
		ProviderURN:  provURN,
	}
	resource2 := &domain.Resource{
		ID:           resourceID2,
		URN:          resourceURN2,
		Type:         "table",
		ProviderType: provType,
		ProviderURN:  provURN,
	}
	groupResource := &domain.Resource{
		ID:  groupID,
		URN: "guardian://group/group-1",
	}

	provider1 := &domain.Provider{
		ID:   "prov-id-1",
		URN:  provURN,
		Type: provType,
		Config: &domain.ProviderConfig{
			Resources: []*domain.ResourceConfig{
				{
					Type: "table",
					Roles: []*domain.Role{
						{
							Name:        "reader",
							Permissions: []interface{}{"select"},
						},
						{
							Name:        "writer",
							Permissions: []interface{}{"select", "insert", "update"},
						},
					},
				},
			},
		},
	}
	activeGrant1 := domain.Grant{
		ID:          grantID,
		Status:      domain.GrantStatusActive,
		AccountID:   botAccountID,
		AccountType: "ram_user",
		ResourceID:  resourceID1,
		Permissions: []string{"select"},
		Resource:    resource1,
	}
	packageMembershipGrant := domain.Grant{
		ID:          "pkg-membership-1",
		Status:      domain.GrantStatusActive,
		AccountID:   botAccountID,
		AccountType: "bot",
		ResourceID:  groupID,
		GroupID:     groupID,
		GroupType:   "package_user",
		Resource:    groupResource,
	}
	packageAccessGrant := domain.Grant{
		ID:          grantID2,
		Status:      domain.GrantStatusActive,
		AccountID:   groupRole,
		AccountType: "ram_role",
		ResourceID:  resourceID2,
		Permissions: []string{"select"},
		Resource:    resource2,
	}

	s.Run("returns error when listing direct grants fails", func() {
		s.setupService()

		dbErr := errors.New("db error")
		s.mockRepo.EXPECT().
			List(mock.Anything, domain.ListGrantsFilter{
				ProviderTypes: []string{provType},
				Statuses:      []string{string(domain.GrantStatusActive)},
				AccountIDs:    []string{botAccountID},
			}).
			Return(nil, dbErr).Once()

		err := s.service.GrantDriftCheck(context.Background(), domain.GrantDriftCheckRequest{
			ProviderTypes: []string{provType},
			BotAccountIDs: []string{botAccountID},
			AdminTeam:     adminTeam,
		})

		s.ErrorIs(err, dbErr)
		s.mockRepo.AssertExpectations(s.T())
	})

	s.Run("returns nil when no active grants exist", func() {
		s.setupService()

		s.mockRepo.EXPECT().
			List(mock.Anything, domain.ListGrantsFilter{
				ProviderTypes: []string{provType},
				Statuses:      []string{string(domain.GrantStatusActive)},
				AccountIDs:    []string{botAccountID},
			}).
			Return(nil, nil).Once()
		s.mockRepo.EXPECT().
			List(mock.Anything, domain.ListGrantsFilter{
				GroupTypes:    []string{"package_user"},
				ProviderTypes: []string{"guardian"},
				Statuses:      []string{string(domain.GrantStatusActive)},
				AccountIDs:    []string{botAccountID},
			}).
			Return(nil, nil).Once()

		err := s.service.GrantDriftCheck(context.Background(), domain.GrantDriftCheckRequest{
			ProviderTypes: []string{provType},
			BotAccountIDs: []string{botAccountID},
			AdminTeam:     adminTeam,
		})

		s.NoError(err)
		s.mockRepo.AssertExpectations(s.T())
		s.mockProviderSvc.AssertNotCalled(s.T(), "Find")
		s.mockAlertManager.AssertNotCalled(s.T(), "NotifyDriftCheck")
	})

	s.Run("returns nil when no providers found", func() {
		s.setupService()

		s.mockRepo.EXPECT().
			List(mock.Anything, domain.ListGrantsFilter{
				ProviderTypes: []string{provType},
				Statuses:      []string{string(domain.GrantStatusActive)},
				AccountIDs:    []string{botAccountID},
			}).
			Return([]domain.Grant{activeGrant1}, nil).Once()
		s.mockRepo.EXPECT().
			List(mock.Anything, domain.ListGrantsFilter{
				GroupTypes:    []string{"package_user"},
				ProviderTypes: []string{"guardian"},
				Statuses:      []string{string(domain.GrantStatusActive)},
				AccountIDs:    []string{botAccountID},
			}).
			Return([]domain.Grant{packageMembershipGrant}, nil).Once()
		s.mockRepo.EXPECT().
			List(mock.Anything, domain.ListGrantsFilter{
				GroupTypes:    []string{"package_access_bot_ram_role"},
				ProviderTypes: []string{provType},
				Statuses:      []string{string(domain.GrantStatusActive)},
				GroupIDs:      []string{groupID},
			}).
			Return([]domain.Grant{packageAccessGrant}, nil).Once()

		s.mockProviderSvc.EXPECT().
			Find(mock.Anything, mock.Anything).
			Return(nil, nil).Once()

		err := s.service.GrantDriftCheck(context.Background(), domain.GrantDriftCheckRequest{
			ProviderTypes: []string{provType},
			BotAccountIDs: []string{botAccountID},
			AdminTeam:     adminTeam,
		})

		s.NoError(err)
		s.mockRepo.AssertExpectations(s.T())
		s.mockProviderSvc.AssertExpectations(s.T())
		s.mockAlertManager.AssertNotCalled(s.T(), "NotifyDriftCheck")
	})

	s.Run("returns nil when all grants are confirmed by the provider", func() {
		s.setupService()

		s.mockRepo.EXPECT().
			List(mock.Anything, domain.ListGrantsFilter{
				ProviderTypes: []string{provType},
				Statuses:      []string{string(domain.GrantStatusActive)},
				AccountIDs:    []string{botAccountID},
			}).
			Return([]domain.Grant{activeGrant1}, nil).Once()
		s.mockRepo.EXPECT().
			List(mock.Anything, domain.ListGrantsFilter{
				GroupTypes:    []string{"package_user"},
				ProviderTypes: []string{"guardian"},
				Statuses:      []string{string(domain.GrantStatusActive)},
				AccountIDs:    []string{botAccountID},
			}).
			Return([]domain.Grant{packageMembershipGrant}, nil).Once()
		s.mockRepo.EXPECT().
			List(mock.Anything, domain.ListGrantsFilter{
				GroupTypes:    []string{"package_access_bot_ram_role"},
				ProviderTypes: []string{provType},
				Statuses:      []string{string(domain.GrantStatusActive)},
				GroupIDs:      []string{groupID},
			}).
			Return([]domain.Grant{packageAccessGrant}, nil).Once()
		s.mockProviderSvc.EXPECT().
			Find(mock.Anything, domain.ListProvidersFilter{
				Types: []string{provType},
				URNs:  []string{provURN},
			}).
			Return([]*domain.Provider{provider1}, nil).Once()

		s.mockProviderSvc.EXPECT().
			ListAccess(mock.Anything, *provider1, mock.MatchedBy(func(resources []*domain.Resource) bool {
				if len(resources) != 2 {
					return false
				}
				seen := map[string]bool{}
				for _, r := range resources {
					switch r.ID {
					case resourceID1:
						seen[resourceID1] = true
					case resourceID2:
						seen[resourceID2] = true
					default:
						return false
					}
				}
				return seen[resourceID1] && seen[resourceID2]
			})).
			Return(domain.MapResourceAccess{
				resourceURN1: []domain.AccessEntry{{
					AccountID:   botAccountID,
					AccountType: "ram_user",
					Permission:  "select",
				}},
				resourceURN2: []domain.AccessEntry{{
					AccountID:   groupRole,
					AccountType: "ram_role",
					Permission:  "select",
				}},
			}, nil).Once()

		err := s.service.GrantDriftCheck(context.Background(), domain.GrantDriftCheckRequest{
			ProviderTypes: []string{provType},
			BotAccountIDs: []string{botAccountID},
			AdminTeam:     adminTeam,
		})

		s.NoError(err)
		s.mockRepo.AssertExpectations(s.T())
		s.mockProviderSvc.AssertExpectations(s.T())
		s.mockAlertManager.AssertNotCalled(s.T(), "NotifyDriftCheck")
	})

	s.Run("detects drift, remediates successfully, and sends notification", func() {
		s.setupService()

		s.mockAuditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Maybe().Return(nil)

		s.mockRepo.EXPECT().
			List(mock.Anything, domain.ListGrantsFilter{
				ProviderTypes: []string{provType},
				Statuses:      []string{string(domain.GrantStatusActive)},
				AccountIDs:    []string{botAccountID},
			}).
			Return([]domain.Grant{activeGrant1}, nil).Once()
		s.mockRepo.EXPECT().
			List(mock.Anything, domain.ListGrantsFilter{
				GroupTypes:    []string{"package_user"},
				ProviderTypes: []string{"guardian"},
				Statuses:      []string{string(domain.GrantStatusActive)},
				AccountIDs:    []string{botAccountID},
			}).
			Return([]domain.Grant{packageMembershipGrant}, nil).Once()
		s.mockRepo.EXPECT().
			List(mock.Anything, domain.ListGrantsFilter{
				GroupTypes:    []string{"package_access_bot_ram_role"},
				ProviderTypes: []string{provType},
				Statuses:      []string{string(domain.GrantStatusActive)},
				GroupIDs:      []string{groupID},
			}).
			Return([]domain.Grant{packageAccessGrant}, nil).Once()
		s.mockProviderSvc.EXPECT().
			Find(mock.Anything, domain.ListProvidersFilter{
				Types: []string{provType},
				URNs:  []string{provURN},
			}).
			Return([]*domain.Provider{provider1}, nil).Once()

		s.mockProviderSvc.EXPECT().
			ListAccess(mock.Anything, *provider1, mock.MatchedBy(func(resources []*domain.Resource) bool {
				if len(resources) != 2 {
					return false
				}
				seen := map[string]bool{}
				for _, r := range resources {
					switch r.ID {
					case resourceID1:
						seen[resourceID1] = true
					case resourceID2:
						seen[resourceID2] = true
					default:
						return false
					}
				}
				return seen[resourceID1] && seen[resourceID2]
			})).
			Return(domain.MapResourceAccess{}, nil).Once()

		// simulate 2 missing access
		s.mockProviderSvc.EXPECT().
			GrantAccess(mock.Anything, mock.MatchedBy(func(g domain.Grant) bool {
				return g.ID == grantID2
			})).Return(nil).Once()
		s.mockProviderSvc.EXPECT().
			GrantAccess(mock.Anything, mock.MatchedBy(func(g domain.Grant) bool {
				return g.ID == grantID
			})).Return(nil).Once()

		s.mockAlertManager.EXPECT().
			NotifyDriftCheck(mock.Anything, mock.MatchedBy(func(req alertmanager.NotifyDriftCheckRequest) bool {
				if req.AdminTeam != adminTeam || len(req.Issues) != 2 {
					return false
				}
				seen := map[string]bool{}
				for _, issue := range req.Issues {
					if issue.RemediationError != "" {
						return false
					}
					seen[issue.Grant.ID] = true
				}
				return seen[grantID] && seen[grantID2]
			})).Return(nil).Once()

		err := s.service.GrantDriftCheck(context.Background(), domain.GrantDriftCheckRequest{
			ProviderTypes: []string{provType},
			BotAccountIDs: []string{botAccountID},
			AdminTeam:     adminTeam,
		})

		s.NoError(err)
		s.mockRepo.AssertExpectations(s.T())
		s.mockProviderSvc.AssertExpectations(s.T())
		s.mockAlertManager.AssertExpectations(s.T())
	})

	s.Run("detects drift and captures remediation failure in notification", func() {
		s.setupService()

		s.mockAuditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Maybe().Return(nil)

		remediationErr := errors.New("provider unavailable")

		s.mockRepo.EXPECT().
			List(mock.Anything, domain.ListGrantsFilter{
				ProviderTypes: []string{provType},
				Statuses:      []string{string(domain.GrantStatusActive)},
				AccountIDs:    []string{botAccountID},
			}).
			Return([]domain.Grant{activeGrant1}, nil).Once()
		s.mockRepo.EXPECT().
			List(mock.Anything, domain.ListGrantsFilter{
				GroupTypes:    []string{"package_user"},
				ProviderTypes: []string{"guardian"},
				Statuses:      []string{string(domain.GrantStatusActive)},
				AccountIDs:    []string{botAccountID},
			}).
			Return([]domain.Grant{packageMembershipGrant}, nil).Once()
		s.mockRepo.EXPECT().
			List(mock.Anything, domain.ListGrantsFilter{
				GroupTypes:    []string{"package_access_bot_ram_role"},
				ProviderTypes: []string{provType},
				Statuses:      []string{string(domain.GrantStatusActive)},
				GroupIDs:      []string{groupID},
			}).
			Return([]domain.Grant{packageAccessGrant}, nil).Once()
		s.mockProviderSvc.EXPECT().
			Find(mock.Anything, domain.ListProvidersFilter{
				Types: []string{provType},
				URNs:  []string{provURN},
			}).
			Return([]*domain.Provider{provider1}, nil).Once()

		s.mockProviderSvc.EXPECT().
			ListAccess(mock.Anything, *provider1, mock.MatchedBy(func(resources []*domain.Resource) bool {
				if len(resources) != 2 {
					return false
				}
				seen := map[string]bool{}
				for _, r := range resources {
					switch r.ID {
					case resourceID1:
						seen[resourceID1] = true
					case resourceID2:
						seen[resourceID2] = true
					default:
						return false
					}
				}
				return seen[resourceID1] && seen[resourceID2]
			})).
			Return(domain.MapResourceAccess{}, nil).Once()

		// simulate 2 missing access, but 1 fails remediation
		s.mockProviderSvc.EXPECT().
			GrantAccess(mock.Anything, mock.MatchedBy(func(g domain.Grant) bool {
				return g.ID == grantID2
			})).Return(nil).Once()
		s.mockProviderSvc.EXPECT().
			GrantAccess(mock.Anything, mock.MatchedBy(func(g domain.Grant) bool {
				return g.ID == grantID
			})).Return(remediationErr).Once()

		s.mockAlertManager.EXPECT().
			NotifyDriftCheck(mock.Anything, mock.MatchedBy(func(req alertmanager.NotifyDriftCheckRequest) bool {
				if req.AdminTeam != adminTeam || len(req.Issues) != 2 {
					return false
				}
				seen := map[string]bool{}
				for _, issue := range req.Issues {
					switch issue.Grant.ID {
					case grantID:
						if issue.RemediationError != remediationErr.Error() {
							return false
						}
					case grantID2:
						if issue.RemediationError != "" {
							return false
						}
					default:
						return false
					}
					seen[issue.Grant.ID] = true
				}
				return seen[grantID] && seen[grantID2]
			})).Return(nil).Once()

		err := s.service.GrantDriftCheck(context.Background(), domain.GrantDriftCheckRequest{
			ProviderTypes: []string{provType},
			BotAccountIDs: []string{botAccountID},
			AdminTeam:     adminTeam,
		})

		s.NoError(err)
		s.mockRepo.AssertExpectations(s.T())
		s.mockProviderSvc.AssertExpectations(s.T())
		s.mockAlertManager.AssertExpectations(s.T())
	})

	s.Run("drift check for multiple permissions on the same grant", func() {
		// this test ensures that if a grant has multiple permissions and only some of them are drifted, the remediation and notification still works as expected
		s.setupService()

		s.mockAuditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Maybe().Return(nil)

		activeGrant := domain.Grant{
			ID:          grantID,
			Status:      domain.GrantStatusActive,
			AccountID:   botAccountID,
			AccountType: "ram_user",
			ResourceID:  resourceID1,
			Role:        "writer",
			Permissions: []string{"select", "insert", "update"},
			Resource:    resource1,
		}

		s.mockRepo.EXPECT().
			List(mock.Anything, domain.ListGrantsFilter{
				ProviderTypes: []string{provType},
				Statuses:      []string{string(domain.GrantStatusActive)},
				AccountIDs:    []string{botAccountID},
			}).
			Return([]domain.Grant{activeGrant}, nil).Once()
		s.mockRepo.EXPECT().
			List(mock.Anything, domain.ListGrantsFilter{
				GroupTypes:    []string{"package_user"},
				ProviderTypes: []string{"guardian"},
				Statuses:      []string{string(domain.GrantStatusActive)},
				AccountIDs:    []string{botAccountID},
			}).
			Return(nil, nil).Once()

		s.mockProviderSvc.EXPECT().
			Find(mock.Anything, domain.ListProvidersFilter{
				Types: []string{provType},
				URNs:  []string{provURN},
			}).
			Return([]*domain.Provider{provider1}, nil).Once()

		s.mockProviderSvc.EXPECT().
			ListAccess(mock.Anything, *provider1, mock.MatchedBy(func(resources []*domain.Resource) bool {
				if len(resources) != 1 {
					return false
				}
				return resources[0].ID == resourceID1
			})).
			Return(domain.MapResourceAccess{
				resourceURN1: []domain.AccessEntry{{
					AccountID:   botAccountID,
					AccountType: "ram_user",
					Permission:  "select",
				}},
			}, nil).Once()

		s.mockProviderSvc.EXPECT().
			GrantAccess(mock.Anything, mock.MatchedBy(func(g domain.Grant) bool {
				return g.ID == grantID && len(g.Permissions) == 3 &&
					contains(g.Permissions, "select") &&
					contains(g.Permissions, "insert") &&
					contains(g.Permissions, "update")
			})).Return(nil).Once()

		s.mockAlertManager.EXPECT().
			NotifyDriftCheck(mock.Anything, mock.MatchedBy(func(req alertmanager.NotifyDriftCheckRequest) bool {
				if req.AdminTeam != adminTeam || len(req.Issues) != 1 {
					return false
				}
				issue := req.Issues[0]
				return issue.Grant.ID == grantID &&
					issue.RemediationError == "" &&
					len(issue.Grant.Permissions) == 3 &&
					contains(issue.Grant.Permissions, "select") &&
					contains(issue.Grant.Permissions, "insert") &&
					contains(issue.Grant.Permissions, "update")
			})).Return(nil).Once()

		err := s.service.GrantDriftCheck(context.Background(), domain.GrantDriftCheckRequest{
			ProviderTypes: []string{provType},
			BotAccountIDs: []string{botAccountID},
			AdminTeam:     adminTeam,
		})

		s.NoError(err)
		s.mockRepo.AssertExpectations(s.T())
		s.mockProviderSvc.AssertExpectations(s.T())
		s.mockAlertManager.AssertExpectations(s.T())
	})
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
