package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// NotificationCard contains delivery/reconciliation metadata only, never bot/API credentials.
type NotificationCard struct {
	CreatedAt        time.Time
	EventID          string
	WorkerURL        string
	MessageID        string
	Closed           bool
	AppealID         string
	Revision         uint32
	Recipient        string
	ApprovalIDs      []string
	LastStateHash    string
	DeliveryDeadline time.Time
	LeaseOwner       string
}

// NotificationCardStateHash is a versioned fingerprint shared with the worker contract.
func NotificationCardStateHash(a *Appeal, ids []string, recipient string) string {
	ordered := append([]string(nil), ids...)
	sort.Strings(ordered)
	h := sha256.New()
	fmt.Fprintf(h, "v5\n%d\n%s\n", a.Revision, a.Status)
	for _, id := range ordered {
		var step *Approval
		for _, candidate := range a.Approvals {
			if candidate.ID == id {
				step = candidate
				break
			}
		}
		if step == nil {
			fmt.Fprintf(h, "%s\nmissing\n", id)
			continue
		}
		allowed := false
		for _, email := range step.Approvers {
			if strings.EqualFold(email, recipient) {
				allowed = true
				break
			}
		}
		fmt.Fprintf(h, "%s\n%s\n%d\n%t\n%t\n", id, step.Status, step.AppealRevision, step.IsStale, allowed)
	}
	planIDs := []string{}
	for _, step := range NotificationApprovalPlan(a, recipient, ids) {
		planIDs = append(planIDs, step.ApprovalID)
	}
	sort.Strings(planIDs)
	fmt.Fprintln(h, "plan")
	for _, id := range planIDs {
		fmt.Fprintln(h, id)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func PendingNotificationCardHash(revision uint32, ids []string, recipient string) string {
	a := &Appeal{Revision: uint(revision), Status: AppealStatusPending}
	for _, id := range ids {
		a.Approvals = append(a.Approvals, &Approval{ID: id, Status: ApprovalStatusPending, AppealRevision: uint(revision), Approvers: []string{recipient}})
	}
	return NotificationCardStateHash(a, ids, recipient)
}

// Expired cards are retired at13 days so the final edit precedes Lark's14-day limit.
func (c NotificationCard) Expired(now time.Time) bool {
	return !c.CreatedAt.IsZero() && !now.Before(c.CreatedAt.Add(13*24*time.Hour))
}
