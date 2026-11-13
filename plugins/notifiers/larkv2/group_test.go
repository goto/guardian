package larkv2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goto/guardian/domain"
)

func approvalItem(appeal, id, name, user string) domain.Notification {
	return domain.Notification{User: user, Message: domain.NotificationMessage{Type: domain.NotificationTypeApproverNotification, Variables: map[string]interface{}{"approval_step": name}}, Approval: &domain.NotificationApproval{AppealID: appeal, ApprovalID: id, Revision: 1}}
}

func TestParallelStepsProduceExactlyOneHTTPNotificationForD(t *testing.T) {
	var received []envelope
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var e envelope
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			t.Error(err)
		}
		received = append(received, e)
		_ = json.NewEncoder(w).Encode(map[string]string{"event_id": e.EventID, "message_id": "om_message", "bot": "pending"})
	}))
	defer server.Close()
	n, _ := New(Config{URL: server.URL})
	items := []domain.Notification{approvalItem("appeal", "b", "Step B", "c@example.com"), approvalItem("appeal", "b", "Step B", "d@example.com"), approvalItem("appeal", "c", "Step C", "D@example.com"), approvalItem("appeal", "c", "Step C", "e@example.com")}
	if errs := n.Notify(context.Background(), items); len(errs) > 0 {
		t.Fatal(errs)
	}
	if len(received) != 3 {
		t.Fatalf("expected three cards, got %d", len(received))
	}
	dCount := 0
	for _, e := range received {
		if e.Recipient == "d@example.com" {
			dCount++
			if len(e.Approval.Steps) != 2 || e.Approval.ApprovalID != "" || e.Approval.Steps[0].ApprovalID != "b" || e.Approval.Steps[1].ApprovalID != "c" {
				t.Fatalf("D's merged card context: %+v", e)
			}
		}
	}
	if dCount != 1 {
		t.Fatalf("D received %d cards", dCount)
	}
	if items[1].Approval.ApprovalID != "b" || items[1].Message.Variables["approval_step"] != "Step B" {
		t.Fatal("grouping changed legacy notifier inputs")
	}
}

func TestGroupingPreservesAppealRevisionAndTypeBoundaries(t *testing.T) {
	items := []domain.Notification{approvalItem("one", "a", "A", "d@example.com"), approvalItem("one", "a", "A", "D@example.com"), approvalItem("two", "a", "A", "d@example.com"), approvalItem("one", "b", "B", "d@example.com")}
	items[3].Approval.Revision = 2
	items = append(items, domain.Notification{User: "d@example.com", Message: domain.NotificationMessage{Type: domain.NotificationTypeAppealApproved}})
	got := groupApprovals(items)
	if len(got) != 4 {
		t.Fatalf("merged distinct appeal/revision/status events: %+v", got)
	}
	if got[0].Approval.ApprovalID != "a" || len(got[0].Approval.Steps) != 0 {
		t.Fatal("duplicate step was not deduplicated")
	}
}

func TestSequentialPlanDoesNotReintroduceFilteredPendingSteps(t *testing.T) {
	n := approvalItem("appeal", "p", "Package admin", "a@example.com")
	n.Approval.PlannedSteps = []domain.NotificationApprovalStep{{ApprovalID: "p", Name: "Package admin"}, {ApprovalID: "filtered", Name: "Filtered parallel step"}, {ApprovalID: "later", Name: "Later", Status: "blocked"}}
	got := groupApprovals([]domain.Notification{n})
	if len(got) != 1 || got[0].Approval.ApprovalID != "p" || len(got[0].Approval.Steps) != 0 {
		t.Fatal("notification criteria were bypassed by expansion")
	}
	n.Approval.PlannedSteps = []domain.NotificationApprovalStep{{ApprovalID: "p", Name: "Package admin"}, {ApprovalID: "later", Name: "Later", Status: "blocked"}}
	got = groupApprovals([]domain.Notification{n})
	if len(got[0].Approval.Steps) != 2 || got[0].Approval.Steps[1].Status != "blocked" {
		t.Fatal("eligible sequence not included")
	}
}
