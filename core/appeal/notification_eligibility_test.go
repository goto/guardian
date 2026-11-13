package appeal

import (
	"context"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
)

func TestTechnicalOutcomesKeepParentsAndHumanActions(t *testing.T) {
	s := &Service{logger: log.NewNoop()}
	child := &domain.Appeal{ID: "child", GroupID: "package", GroupType: "package_user", AccountType: "sso_user", Role: "member", Resource: &domain.Resource{ProviderType: "alicloud_sso", Type: "group"}}
	parent := &domain.Appeal{ID: "parent", GroupID: "package", GroupType: "package_user", AccountType: "user", Resource: &domain.Resource{ProviderType: "guardian", Type: "package"}}
	var notifications []domain.Notification
	for _, id := range []string{child.ID, parent.ID, "unknown"} {
		for _, kind := range []string{domain.NotificationTypeAppealApproved, domain.NotificationTypeOnBehalfAppealApproved, domain.NotificationTypeAppealRejected, domain.NotificationTypeApproverNotification, domain.NotificationTypeNewComment} {
			notifications = append(notifications, domain.Notification{Labels: map[string]string{"appeal_id": id}, Message: domain.NotificationMessage{Type: kind}})
		}
	}
	got := s.filterTechnicalNotifications(context.Background(), notifications, child, parent, nil)
	if len(got) != 12 {
		t.Fatalf("got %d notifications, want 12", len(got))
	}
	for _, n := range got {
		if n.Labels["appeal_id"] == "child" && n.Message.Type != domain.NotificationTypeApproverNotification && n.Message.Type != domain.NotificationTypeNewComment {
			t.Fatalf("child outcome leaked: %s", n.Message.Type)
		}
	}
	if len(notifications) != 15 {
		t.Fatal("input batch mutated")
	}
}
