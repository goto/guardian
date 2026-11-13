package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
)

type reminderRecorder struct{ notifications []domain.Notification }

type reminderGrantService struct {
	grantService
	grants []domain.Grant
	calls  int
}

func (s *reminderGrantService) List(_ context.Context, _ domain.ListGrantsFilter) ([]domain.Grant, error) {
	s.calls++
	if s.calls == 1 {
		return s.grants, nil
	}
	return nil, nil
}

func (r *reminderRecorder) Notify(_ context.Context, n []domain.Notification) []error {
	r.notifications = append(r.notifications, n...)
	return []error{errors.New("synthetic delivery failure")}
}

func TestExpiryReminderKeepsParentAndSkipsTechnicalChildren(t *testing.T) {
	expires := time.Now().Add(3 * 24 * time.Hour)
	parent := domain.Grant{ID: "parent", GroupID: "package", GroupType: "package_user", AccountType: "user", AccountID: "holder@example.com", CreatedBy: "requester@example.com", Role: "member", ExpirationDate: &expires, Resource: &domain.Resource{ProviderType: "guardian", Type: "package"}}
	child := parent
	child.ID, child.AccountType, child.AccountID = "child", "sso_user", "sso-id"
	child.Resource = &domain.Resource{ProviderType: "alicloud_sso", Type: "group"}
	childWithAppeal := child
	childWithAppeal.ID, childWithAppeal.AppealID = "child-with-appeal", "technical-appeal"
	direct := parent
	direct.ID, direct.GroupID, direct.GroupType = "direct", "", ""
	direct.AccountID = direct.CreatedBy
	direct.Resource = &domain.Resource{ProviderType: "maxcompute", Type: "table"}
	service := &reminderGrantService{grants: []domain.Grant{parent, child, childWithAppeal, direct, {}}}
	recorder := &reminderRecorder{}
	h := handler{grantService: service, notifier: recorder, logger: log.NewNoop()}
	if err := h.GrantExpirationReminder(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(recorder.notifications) != 3 {
		t.Fatalf("got %d notifications, want parent requester+holder and direct", len(recorder.notifications))
	}
	for _, n := range recorder.notifications {
		if n.Labels["grant_id"] != "parent" && n.Labels["grant_id"] != "direct" {
			t.Fatalf("technical notification leaked: %v", n.Labels)
		}
	}
	if service.calls != 3 {
		t.Fatalf("delivery failure stopped later windows: %d calls", service.calls)
	}
}
