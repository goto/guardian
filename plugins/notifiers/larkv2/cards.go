package larkv2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/goto/guardian/domain"
)

type CardStore interface {
	Ready(context.Context) error
	Prepare(context.Context, domain.NotificationCard, time.Duration) error
	Ensure(context.Context, domain.NotificationCard, time.Duration) (bool, error)
	Confirm(context.Context, string, string) error
	Claim(context.Context, string, string, int) ([]domain.NotificationCard, error)
	Complete(context.Context, domain.NotificationCard, string, bool, time.Duration) error
	Retry(context.Context, domain.NotificationCard, time.Duration) error
}
type AppealReader interface {
	GetByID(context.Context, string) (*domain.Appeal, error)
}

func (n *Notifier) ConfigureCards(store CardStore, reader AppealReader) {
	n.store = store
	n.reader = reader
}
func (n *Notifier) workerURL() string { return strings.TrimSuffix(n.endpoint, "/v1/notifications") }

func cardForDelivery(eventID string, item domain.Notification, workerURL string) domain.NotificationCard {
	ids := []string{}
	if item.Approval.ApprovalID != "" {
		ids = append(ids, item.Approval.ApprovalID)
	} else {
		for _, step := range item.Approval.Steps {
			ids = append(ids, step.ApprovalID)
		}
	}
	return domain.NotificationCard{EventID: eventID, WorkerURL: workerURL, AppealID: item.Approval.AppealID, Revision: item.Approval.Revision, Recipient: strings.ToLower(strings.TrimSpace(item.User)), ApprovalIDs: ids, LastStateHash: domain.PendingNotificationCardHash(item.Approval.Revision, ids, item.User)}
}

// ReconcileCards uses durable receipt leases and authoritative database reads, so console/API
// changes and restarts do not depend on a Lark callback or a best effort state-change event.
func (n *Notifier) ReconcileCards(ctx context.Context) error {
	if n.store == nil || n.reader == nil {
		return nil
	}
	cards, err := n.store.Claim(ctx, n.workerURL(), uuid.NewString(), 10)
	if err != nil {
		return errors.New("claiming notification cards failed")
	}
	failures := make(chan struct{}, len(cards))
	var wg sync.WaitGroup
	slots := make(chan struct{}, 4)
	for _, card := range cards {
		if ctx.Err() != nil {
			break
		}
		slots <- struct{}{}
		wg.Add(1)
		go func(card domain.NotificationCard) {
			defer wg.Done()
			defer func() { <-slots }()
			if n.reconcileCard(ctx, card) {
				failures <- struct{}{}
			}
		}(card)
	}
	wg.Wait()
	if len(failures) > 0 {
		return errors.New("notification card updates require retry")
	}
	return nil
}

func (n *Notifier) reconcileCard(parent context.Context, card domain.NotificationCard) (failed bool) {
	ctx, cancel := context.WithTimeout(parent, 25*time.Second)
	defer cancel()
	retry := func(delay time.Duration) { failed = true; _ = n.store.Retry(ctx, card, delay) }
	if card.MessageID == "" && !card.DeliveryDeadline.IsZero() && time.Now().After(card.DeliveryDeadline) {
		if err := n.store.Complete(ctx, card, card.LastStateHash, true, 0); err != nil {
			failed = true
		}
		return
	}
	// If the entire final-edit window was unavailable, stop retrying after the
	// platform's maximum update age. Never send a replacement notification here.
	if card.MessageID != "" && !card.DeliveryDeadline.IsZero() && time.Now().After(card.DeliveryDeadline.Add(14*24*time.Hour+time.Minute)) {
		if err := n.store.Complete(ctx, card, card.LastStateHash, true, 0); err != nil {
			failed = true
		}
		return
	}
	appeal, err := n.reader.GetByID(ctx, card.AppealID)
	if err != nil || appeal == nil {
		retry(15 * time.Second)
		return
	}
	if card.MessageID == "" {
		item := recoveryNotification(card, appeal)
		data, err := json.Marshal(envelope{EventID: card.EventID, Recipient: card.Recipient, Type: item.Message.Type, Variables: presentationVariables(item.Message.Variables), Approval: item.Approval})
		if err != nil || len(data) > 64*1024 {
			retry(15 * time.Second)
			return
		}
		if _, _, err := n.attempt(ctx, data, card.EventID, true); err != nil {
			retry(15 * time.Second)
		}
		return
	}
	if appeal.Status == domain.AppealStatusPending && uint32(appeal.Revision) == card.Revision && !card.Expired(time.Now()) {
		seen := map[string]bool{}
		for _, id := range card.ApprovalIDs {
			seen[id] = true
		}
		extended := card
		extended.ApprovalIDs = append([]string(nil), card.ApprovalIDs...)
		canExtend := true
		for _, step := range domain.NotificationApprovalPlan(appeal, card.Recipient, nil) {
			if !seen[step.ApprovalID] {
				if step.Status != "blocked" {
					canExtend = false
					break
				}
				extended.ApprovalIDs = append(extended.ApprovalIDs, step.ApprovalID)
				seen[step.ApprovalID] = true
			}
		}
		if canExtend && len(extended.ApprovalIDs) != len(card.ApprovalIDs) {
			if _, err := n.store.Ensure(ctx, extended, 0); err != nil {
				retry(15 * time.Second)
			}
			// Ensure fences this lease and schedules a repaint of the expanded plan.
			return
		}
	}
	hash := domain.NotificationCardStateHash(appeal, card.ApprovalIDs, card.Recipient)
	terminal := uint32(appeal.Revision) != card.Revision || appeal.Status != domain.AppealStatusPending
	if hash == card.LastStateHash && !card.Expired(time.Now()) {
		if err := n.store.Complete(ctx, card, hash, terminal, 5*time.Second); err != nil {
			failed = true
		}
		return
	}
	request := struct {
		MessageID   string   `json:"message_id"`
		AppealID    string   `json:"appeal_id"`
		Revision    uint32   `json:"revision"`
		Recipient   string   `json:"recipient"`
		ApprovalIDs []string `json:"approval_ids"`
	}{card.MessageID, card.AppealID, card.Revision, card.Recipient, card.ApprovalIDs}
	data, _ := json.Marshal(request)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.workerURL()+"/v1/cards/refresh", bytes.NewReader(data))
	if err != nil {
		retry(15 * time.Second)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.http.Do(req)
	if err != nil {
		retry(15 * time.Second)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == 409 {
		if err := n.store.Retry(ctx, card, time.Second); err != nil {
			failed = true
		}
		return
	}
	if resp.StatusCode != 200 {
		retry(15 * time.Second)
		return
	}
	var result struct {
		MessageID string `json:"message_id"`
		StateHash string `json:"state_hash"`
		Terminal  bool   `json:"terminal"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&result) != nil || result.MessageID != card.MessageID || len(result.StateHash) != 64 {
		retry(15 * time.Second)
		return
	}
	if err := n.store.Complete(ctx, card, result.StateHash, result.Terminal, 5*time.Second); err != nil {
		failed = true
	}
	return
}

func recoveryNotification(card domain.NotificationCard, a *domain.Appeal) domain.Notification {
	context := &domain.NotificationApproval{AppealID: card.AppealID, Revision: card.Revision}
	for _, id := range card.ApprovalIDs {
		name := id
		for _, step := range a.Approvals {
			if step.ID == id {
				name = step.Name
				break
			}
		}
		context.Steps = append(context.Steps, domain.NotificationApprovalStep{ApprovalID: id, Name: name})
	}
	vars := map[string]interface{}{"appeal_id": a.ID, "requestor": a.CreatedBy, "account_id": a.AccountID, "account_type": a.AccountType, "group_id": a.GroupID, "group_type": a.GroupType, "role": a.Role, "details": a.Details, "duration": "Not specified"}
	if a.Options != nil && a.Options.Duration != "" {
		vars["duration"] = a.Options.Duration
	}
	if a.Resource != nil {
		vars["resource_id"] = a.Resource.ID
		vars["resource_display_name"] = a.Resource.Name
		vars["resource_urn"] = a.Resource.URN
		vars["resource_name"] = a.Resource.Name
		vars["provider_type"] = a.Resource.ProviderType
		vars["resource_type"] = a.Resource.Type
	}
	return domain.Notification{User: card.Recipient, Message: domain.NotificationMessage{Type: domain.NotificationTypeApproverNotification, Variables: vars}, Approval: context}
}
