package larkv2

import (
	"strings"

	"github.com/goto/guardian/domain"
)

// Group only within one committed notification batch. Legacy notifiers retain their per-step
// links, while v2 sends one card for each appeal, revision and recipient.
func groupApprovals(items []domain.Notification) []domain.Notification {
	type key struct {
		appeal, recipient string
		revision          uint32
	}
	positions := map[key]int{}
	var result []domain.Notification
	for _, item := range items {
		if item.Message.Type != domain.NotificationTypeApproverNotification || item.Approval == nil || item.Approval.AppealID == "" || (item.Approval.ApprovalID == "" && len(item.Approval.Steps) == 0) {
			result = append(result, item)
			continue
		}
		k := key{item.Approval.AppealID, strings.ToLower(strings.TrimSpace(item.User)), item.Approval.Revision}
		index, found := positions[k]
		if !found {
			index = len(result)
			positions[k] = index
			copyItem := item
			copyItem.User = k.recipient
			copyContext := *item.Approval
			copyContext.Steps = nil
			copyItem.Approval = &copyContext
			copyItem.Message.Variables = map[string]interface{}{}
			for name, value := range item.Message.Variables {
				copyItem.Message.Variables[name] = value
			}
			result = append(result, copyItem)
		}
		steps := append([]domain.NotificationApprovalStep(nil), item.Approval.Steps...)
		if item.Approval.ApprovalID != "" {
			name, _ := item.Message.Variables["approval_step"].(string)
			steps = append(steps, domain.NotificationApprovalStep{ApprovalID: item.Approval.ApprovalID, Name: name})
		}
		for _, step := range steps {
			duplicate := false
			for _, existing := range result[index].Approval.Steps {
				if existing.ApprovalID == step.ApprovalID {
					duplicate = true
					break
				}
			}
			if !duplicate {
				result[index].Approval.Steps = append(result[index].Approval.Steps, step)
			}
		}
	}
	for _, index := range positions {
		item := &result[index]
		if len(item.Approval.Steps) == 1 {
			item.Approval.ApprovalID = item.Approval.Steps[0].ApprovalID
			item.Message.Variables["approval_step"] = item.Approval.Steps[0].Name
			item.Approval.Steps = nil
		} else {
			item.Approval.ApprovalID = ""
			names := make([]string, 0, len(item.Approval.Steps))
			for _, step := range item.Approval.Steps {
				names = append(names, step.Name)
			}
			item.Message.Variables["approval_step"] = strings.Join(names, ", ")
		}
	}
	return result
}
