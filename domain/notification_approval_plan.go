package domain

import (
	"sort"
	"strings"
)

// NotificationApprovalPlan includes ready manual steps and consecutive future steps this
// actor can complete. A stage with another approver or unresolved automatic policy is a barrier.
// allowed=nil is for initial notification construction; otherwise IDs are receipt-bounded.
func NotificationApprovalPlan(a *Appeal, recipient string, allowed []string) []NotificationApprovalStep {
	result := []NotificationApprovalStep{}
	if a == nil || a.Status != AppealStatusPending {
		return result
	}
	permitted := map[string]bool{}
	for _, id := range allowed {
		permitted[id] = true
	}
	stages := map[int][]*Approval{}
	var indices []int
	for _, step := range a.Approvals {
		if step == nil || step.IsStale || step.AppealRevision != a.Revision {
			continue
		}
		if _, ok := stages[step.Index]; !ok {
			indices = append(indices, step.Index)
		}
		stages[step.Index] = append(stages[step.Index], step)
	}
	sort.Ints(indices)
	started := false
	for _, index := range indices {
		unresolved, canFinish := false, true
		var selected []NotificationApprovalStep
		ready := false
		for _, step := range stages[index] {
			if step.Status == ApprovalStatusApproved || step.Status == ApprovalStatusSkipped {
				continue
			}
			unresolved = true
			eligible := step.IsManualApproval() && step.IsExistingApprover(recipient) && (allowed == nil || permitted[step.ID])
			canApprove := eligible && !(step.DontAllowSelfApproval && strings.EqualFold(a.CreatedBy, recipient))
			if step.Status == ApprovalStatusPending && eligible {
				selected = append(selected, NotificationApprovalStep{ApprovalID: step.ID, Name: step.Name})
				ready = true
			} else if step.Status == ApprovalStatusBlocked && started && canApprove {
				selected = append(selected, NotificationApprovalStep{ApprovalID: step.ID, Name: step.Name, Status: ApprovalStatusBlocked})
			}
			if !canApprove || (step.Status != ApprovalStatusPending && step.Status != ApprovalStatusBlocked) {
				canFinish = false
			}
		}
		if !unresolved {
			continue
		}
		if !started && !ready {
			break
		}
		started = true
		result = append(result, selected...)
		if !canFinish {
			break
		}
	}
	return result
}
