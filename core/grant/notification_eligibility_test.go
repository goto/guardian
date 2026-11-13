package grant_test

import (
	"context"
	"testing"
	"time"

	"github.com/goto/guardian/core/grant"
	"github.com/goto/guardian/core/grant/mocks"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/stretchr/testify/mock"
)

type eligibilityRecorder struct{ batches chan []domain.Notification }

func (r *eligibilityRecorder) Notify(_ context.Context, n []domain.Notification) []error {
	r.batches <- n
	return nil
}

func TestTechnicalGrantRevocationStillRevokesAndAudits(t *testing.T) {
	repo := new(mocks.Repository)
	provider := new(mocks.ProviderService)
	audit := new(mocks.AuditLogger)
	recorder := &eligibilityRecorder{batches: make(chan []domain.Notification, 1)}
	g := &domain.Grant{ID: "child", Status: domain.GrantStatusActive, AccountType: "sso_user", GroupID: "package", GroupType: "package_user", Role: "member", Resource: &domain.Resource{ProviderType: "alicloud_sso", Type: "group"}}
	repo.On("GetByID", mock.Anything, g.ID).Return(g, nil).Once()
	repo.On("Update", mock.Anything, mock.MatchedBy(func(g *domain.Grant) bool { return g.Status == domain.GrantStatusInactive })).Return(nil).Once()
	provider.On("RevokeAccess", mock.Anything, mock.Anything).Return(nil).Once()
	audited := make(chan struct{})
	audit.On("Log", mock.Anything, grant.AuditKeyRevoke, mock.Anything).Run(func(mock.Arguments) { close(audited) }).Return(nil).Once()
	s := grant.NewService(grant.ServiceDeps{Repository: repo, ProviderService: provider, AuditLogger: audit, Notifier: recorder, Logger: log.NewNoop()})
	got, err := s.Revoke(context.Background(), g.ID, "actor@example.com", "Automatically revoked")
	if err != nil || got.Status != domain.GrantStatusInactive {
		t.Fatalf("revoke failed: %v, %v", got, err)
	}
	select {
	case <-audited:
	case <-time.After(3 * time.Second):
		t.Fatal("audit not recorded")
	}
	select {
	case n := <-recorder.batches:
		t.Fatalf("technical notification sent: %v", n)
	default:
	}
	repo.AssertExpectations(t)
	provider.AssertExpectations(t)
}

func TestDormancyFiltersMessagesWithoutSkippingGrantUpdates(t *testing.T) {
	for _, onlyChildren := range []bool{false, true} {
		t.Run(map[bool]string{false: "mixed", true: "children only"}[onlyChildren], func(t *testing.T) {
			repo := new(mocks.Repository)
			provider := new(mocks.ProviderService)
			recorder := &eligibilityRecorder{batches: make(chan []domain.Notification, 1)}
			p := &domain.Provider{ID: "provider"}
			child := domain.Grant{ID: "child", Owner: "owner@example.com", AccountType: "ram_role", GroupID: "package", GroupType: "package_access_bot_ram_role", Resource: &domain.Resource{ProviderType: "maxcompute", Type: "table"}}
			grants := []domain.Grant{child}
			if !onlyChildren {
				parent := child
				parent.ID = "parent"
				parent.GroupType = "package_access"
				grants = append(grants, parent)
			}
			provider.On("GetByID", mock.Anything, p.ID).Return(p, nil).Once()
			repo.On("List", mock.Anything, mock.Anything).Return(grants, nil).Once()
			provider.On("ListActivities", mock.Anything, *p, mock.Anything).Return([]*domain.Activity{}, nil).Once()
			provider.On("CorrelateGrantActivities", mock.Anything, *p, mock.Anything, mock.Anything).Return(nil).Once()
			repo.On("BulkUpsert", mock.Anything, mock.MatchedBy(func(gs []*domain.Grant) bool {
				if len(gs) != len(grants) {
					return false
				}
				for _, g := range gs {
					if g.ExpirationDate == nil {
						return false
					}
				}
				return true
			})).Return(nil).Once()
			s := grant.NewService(grant.ServiceDeps{Repository: repo, ProviderService: provider, Notifier: recorder, Logger: log.NewNoop()})
			if err := s.DormancyCheck(context.Background(), domain.DormancyCheckCriteria{ProviderID: p.ID, Period: 30 * 24 * time.Hour, RetainDuration: 7 * 24 * time.Hour}); err != nil {
				t.Fatal(err)
			}
			select {
			case batch := <-recorder.batches:
				if onlyChildren {
					if len(batch) != 0 {
						t.Fatal("empty owner digest was sent")
					}
					break
				}
				if len(batch) != 1 || batch[0].Labels["grant_ids"] != "parent" {
					t.Fatalf("unexpected digest: %v", batch)
				}
				items := batch[0].Message.Variables["dormant_grants"].([]map[string]interface{})
				if len(items) != 1 || items[0]["id"] != "parent" {
					t.Fatalf("technical grant in digest: %v", items)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("digest completion not observed")
			}
			repo.AssertExpectations(t)
			provider.AssertExpectations(t)
		})
	}
}
