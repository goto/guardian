package appeal

import (
	"errors"
	"testing"

	"github.com/goto/guardian/domain"
)

func TestApprovalIDRejectsObsoleteRevision(t *testing.T) {
	for _, action := range []string{"approve", "reject"} {
		for _, stale := range []bool{false, true} {
			t.Run(action+map[bool]string{false: "/revision", true: "/stale"}[stale], func(t *testing.T) {
				a := &domain.Appeal{ID: "appeal", Status: domain.AppealStatusPending, Revision: 2, Approvals: []*domain.Approval{{ID: "old-id", Name: "owner", Status: domain.ApprovalStatusPending, IsStale: stale, AppealRevision: 1, Approvers: []string{"approver@example.com"}}}}
				err := applyApprovalMutation(a, domain.ApprovalAction{AppealID: a.ID, ApprovalName: "old-id", Actor: "approver@example.com", Action: action}, nil)
				if !errors.Is(err, ErrApprovalNotEligibleForAction) {
					t.Fatalf("expected stale-step rejection, got %v", err)
				}
				if a.Approvals[0].Actor != nil || a.Approvals[0].Status != domain.ApprovalStatusPending {
					t.Fatal("obsolete step was mutated")
				}
			})
		}
	}
}

func TestApprovalNotificationIncludesExactContext(t *testing.T) {
	s := &Service{}
	a := &domain.Appeal{ID: "appeal", Revision: 3, Approvals: []*domain.Approval{{ID: "approval", Name: "owner", Status: domain.ApprovalStatusPending, AppealRevision: 3, Approvers: []string{"approver@example.com"}}}, Resource: &domain.Resource{Name: "Example"}, Options: &domain.AppealOptions{Duration: "24h"}}
	notifications := s.getApprovalNotifications(nil, a)
	if len(notifications) != 1 || notifications[0].Approval == nil {
		t.Fatal("missing approval notification context")
	}
	context := notifications[0].Approval
	if context.AppealID != "appeal" || context.ApprovalID != "approval" || context.Revision != 3 {
		t.Fatalf("wrong context: %+v", context)
	}
}

func TestSelfApprovalRemainsForbiddenAfterLarkEmailNormalization(t *testing.T) {
	a := &domain.Appeal{ID: "appeal", CreatedBy: "APPROVER@example.com", Status: domain.AppealStatusPending, Approvals: []*domain.Approval{{ID: "approval", Name: "owner", Status: domain.ApprovalStatusPending, Approvers: []string{"approver@example.com"}}}}
	policy := &domain.Policy{Steps: []*domain.Step{{Name: "owner", DontAllowSelfApproval: true}}}
	err := applyApprovalMutation(a, domain.ApprovalAction{ApprovalName: "approval", Actor: "approver@example.com", Action: "approve"}, policy)
	if !errors.Is(err, ErrSelfApprovalNotAllowed) {
		t.Fatalf("self approval was not blocked: %v", err)
	}
	if a.Approvals[0].Status != domain.ApprovalStatusPending {
		t.Fatal("self-approved step changed status")
	}
}
