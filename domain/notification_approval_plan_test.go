package domain_test

import (
	"github.com/goto/guardian/domain"
	"testing"
)

func planAppeal() *domain.Appeal {
	return &domain.Appeal{Status: "pending", Revision: 2, CreatedBy: "requester@example.com", Approvals: []*domain.Approval{
		{ID: "p", Name: "Package admin", Index: 0, Status: "pending", AppealRevision: 2, Approvers: []string{"a@example.com", "b@example.com"}},
		{ID: "m", Name: "Manager", Index: 1, Status: "blocked", AppealRevision: 2, Approvers: []string{"a@example.com"}},
		{ID: "l", Name: "Lead", Index: 2, Status: "blocked", AppealRevision: 2, Approvers: []string{"a@example.com"}},
	}}
}
func TestNotificationApprovalPlanHonorsStageBarriers(t *testing.T) {
	for _, mode := range []string{"consecutive", "other-user", "parallel-barrier", "automatic-barrier", "receipt-bound", "self-approval", "blocked-only", "terminal"} {
		t.Run(mode, func(t *testing.T) {
			a := planAppeal()
			var allowed []string
			want := 3
			switch mode {
			case "other-user":
				a.Approvals[1].Approvers = []string{"b@example.com"}
				want = 1
			case "parallel-barrier":
				a.Approvals = append(a.Approvals, &domain.Approval{ID: "other", Index: 0, Status: "pending", AppealRevision: 2, Approvers: []string{"b@example.com"}})
				want = 1
			case "automatic-barrier":
				a.Approvals[1].Approvers = nil
				want = 1
			case "receipt-bound":
				allowed = []string{"p", "l"}
				want = 1
			case "self-approval":
				a.CreatedBy = "a@example.com"
				a.Approvals[1].DontAllowSelfApproval = true
				want = 1
			case "blocked-only":
				a.Approvals[0].Approvers = []string{"b@example.com"}
				want = 0
			case "terminal":
				a.Status = "approved"
				want = 0
			}
			got := domain.NotificationApprovalPlan(a, "a@example.com", allowed)
			if len(got) != want {
				t.Fatalf("plan %+v, want %d", got, want)
			}
			if want == 3 && (got[0].ApprovalID != "p" || got[1].ApprovalID != "m" || got[2].ApprovalID != "l" || got[1].Status != "blocked") {
				t.Fatal("plan lost order/status")
			}
		})
	}
}
