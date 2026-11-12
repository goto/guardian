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
	fmt.Fprintf(h, "v1\n%d\n%s\n", a.Revision, a.Status)
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
	return hex.EncodeToString(h.Sum(nil))
}

func PendingNotificationCardHash(revision uint32, ids []string, recipient string) string {
	a := &Appeal{Revision: uint(revision), Status: AppealStatusPending}
	for _, id := range ids {
		a.Approvals = append(a.Approvals, &Approval{ID: id, Status: ApprovalStatusPending, AppealRevision: uint(revision), Approvers: []string{recipient}})
	}
	return NotificationCardStateHash(a, ids, recipient)
}
