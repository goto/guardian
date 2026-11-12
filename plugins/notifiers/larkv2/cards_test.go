package larkv2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/goto/guardian/domain"
)

type memoryCardStore struct {
	mu              sync.Mutex
	cards           map[string]domain.NotificationCard
	closed          map[string]bool
	confirmFailures int
	retries         int
}

func newMemoryCardStore() *memoryCardStore {
	return &memoryCardStore{cards: map[string]domain.NotificationCard{}, closed: map[string]bool{}}
}
func (s *memoryCardStore) Ready(context.Context) error { return nil }
func (s *memoryCardStore) Prepare(ctx context.Context, c domain.NotificationCard, lease time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.cards[c.EventID]; !ok {
		c.DeliveryDeadline = time.Now().Add(55 * time.Minute)
		s.cards[c.EventID] = c
	}
	return nil
}
func (s *memoryCardStore) Confirm(ctx context.Context, id, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.confirmFailures > 0 {
		s.confirmFailures--
		return errors.New("temporary DB error")
	}
	c := s.cards[id]
	c.MessageID = message
	c.LeaseOwner = ""
	s.cards[id] = c
	return nil
}
func (s *memoryCardStore) Claim(ctx context.Context, url, owner string, limit int) ([]domain.NotificationCard, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []domain.NotificationCard
	for id, c := range s.cards {
		if !s.closed[id] && c.WorkerURL == url && c.LeaseOwner == "" {
			c.LeaseOwner = owner
			s.cards[id] = c
			result = append(result, c)
			if len(result) == limit {
				break
			}
		}
	}
	return result, nil
}
func (s *memoryCardStore) Complete(ctx context.Context, c domain.NotificationCard, hash string, closed bool, delay time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.cards[c.EventID]
	if v.LeaseOwner == c.LeaseOwner {
		v.LastStateHash = hash
		v.LeaseOwner = ""
		s.cards[c.EventID] = v
		s.closed[c.EventID] = closed
	}
	return nil
}
func (s *memoryCardStore) Retry(ctx context.Context, c domain.NotificationCard, delay time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.cards[c.EventID]
	if v.LeaseOwner == c.LeaseOwner {
		v.LeaseOwner = ""
		s.cards[c.EventID] = v
		s.retries++
	}
	return nil
}

type cardReader struct{ appeal *domain.Appeal }

func (r cardReader) GetByID(context.Context, string) (*domain.Appeal, error) { return r.appeal, nil }
func trackedAppeal(status string) *domain.Appeal {
	return &domain.Appeal{ID: "appeal", Revision: 2, Status: status, Resource: &domain.Resource{Name: "Example"}, Approvals: []*domain.Approval{{ID: "approval-1", Name: "Owner", Status: status, AppealRevision: 2, Approvers: []string{"a@example.com", "b@example.com"}}}}
}

func TestSiblingReceiptsReconcileAfterNotifierRestart(t *testing.T) {
	store := newMemoryCardStore()
	a := trackedAppeal("approved")
	var mu sync.Mutex
	var messages []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/cards/refresh" {
			t.Error("reconciliation delivered a new message")
		}
		var request struct {
			MessageID   string   `json:"message_id"`
			Recipient   string   `json:"recipient"`
			ApprovalIDs []string `json:"approval_ids"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		mu.Lock()
		messages = append(messages, request.MessageID)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"message_id": request.MessageID, "state_hash": domain.NotificationCardStateHash(a, request.ApprovalIDs, request.Recipient), "terminal": true})
	}))
	defer server.Close()
	for _, person := range []string{"a", "b"} {
		id := uuid.NewString()
		store.cards[id] = domain.NotificationCard{EventID: id, WorkerURL: server.URL, MessageID: "om_" + person, AppealID: a.ID, Revision: 2, Recipient: person + "@example.com", ApprovalIDs: []string{"approval-1"}, LastStateHash: domain.PendingNotificationCardHash(2, []string{"approval-1"}, person+"@example.com")}
	}
	restarted, _ := New(Config{URL: server.URL})
	restarted.ConfigureCards(store, cardReader{a})
	if err := restarted.ReconcileCards(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	seen := map[string]bool{}
	for _, id := range messages {
		seen[id] = true
	}
	if !seen["om_a"] || !seen["om_b"] || len(messages) != 2 {
		t.Fatalf("sibling fanout missing: %+v", messages)
	}
	for id := range store.cards {
		if !store.closed[id] {
			t.Fatal("terminal receipt remained active")
		}
	}
}

func TestUnchangedStateDoesNotResetAnOpenCardForm(t *testing.T) {
	store := newMemoryCardStore()
	a := trackedAppeal("pending")
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(500) }))
	defer server.Close()
	id := uuid.NewString()
	store.cards[id] = domain.NotificationCard{EventID: id, WorkerURL: server.URL, MessageID: "om_b", AppealID: a.ID, Revision: 2, Recipient: "b@example.com", ApprovalIDs: []string{"approval-1"}, LastStateHash: domain.PendingNotificationCardHash(2, []string{"approval-1"}, "b@example.com")}
	n, _ := New(Config{URL: server.URL})
	n.ConfigureCards(store, cardReader{a})
	if err := n.ReconcileCards(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("unchanged pending card was rewritten")
	}
}

func TestPendingDeliveryRecoveryReusesPersistedEventID(t *testing.T) {
	store := newMemoryCardStore()
	a := trackedAppeal("pending")
	id := uuid.NewString()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var e envelope
		_ = json.NewDecoder(r.Body).Decode(&e)
		if e.EventID != id {
			t.Error("recovery generated a new event ID")
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"event_id": id, "message_id": "om_recovered", "bot": "pending"})
	}))
	defer server.Close()
	store.cards[id] = domain.NotificationCard{EventID: id, WorkerURL: server.URL, AppealID: a.ID, Revision: 2, Recipient: "b@example.com", ApprovalIDs: []string{"approval-1"}, LastStateHash: domain.PendingNotificationCardHash(2, []string{"approval-1"}, "b@example.com"), DeliveryDeadline: time.Now().Add(time.Hour)}
	n, _ := New(Config{URL: server.URL})
	n.ConfigureCards(store, cardReader{a})
	if err := n.ReconcileCards(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || store.cards[id].MessageID != "om_recovered" {
		t.Fatal("pending receipt did not recover")
	}
}

func TestDeliveryConfirmsDurableReceiptWithStableRetry(t *testing.T) {
	store := newMemoryCardStore()
	store.confirmFailures = 1
	calls := 0
	event := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var e envelope
		_ = json.NewDecoder(r.Body).Decode(&e)
		if event == "" {
			event = e.EventID
		} else if event != e.EventID {
			t.Error("confirmation retry changed event")
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"event_id": e.EventID, "message_id": "om_b", "bot": "pending"})
	}))
	defer server.Close()
	n, _ := New(Config{URL: server.URL})
	n.ConfigureCards(store, cardReader{trackedAppeal("pending")})
	n.delays = []time.Duration{0, 0}
	if errs := n.Notify(context.Background(), []domain.Notification{approvalItem("appeal", "approval-1", "Owner", "b@example.com")}); len(errs) > 0 {
		t.Fatal(errs)
	}
	if calls != 2 || len(store.cards) != 1 || store.cards[event].MessageID != "om_b" {
		t.Fatal("durable delivery retry did not converge")
	}
}

func TestFailedSiblingUpdateRemainsRetryableAfterRestart(t *testing.T) {
	store := newMemoryCardStore()
	a := trackedAppeal("approved")
	fail := true
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if fail {
			w.WriteHeader(503)
			return
		}
		var request struct {
			MessageID string `json:"message_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"message_id": request.MessageID, "state_hash": domain.NotificationCardStateHash(a, []string{"approval-1"}, "b@example.com"), "terminal": true})
	}))
	defer server.Close()
	id := uuid.NewString()
	store.cards[id] = domain.NotificationCard{EventID: id, WorkerURL: server.URL, MessageID: "om_b", AppealID: a.ID, Revision: 2, Recipient: "b@example.com", ApprovalIDs: []string{"approval-1"}, LastStateHash: domain.PendingNotificationCardHash(2, []string{"approval-1"}, "b@example.com")}
	n, _ := New(Config{URL: server.URL})
	n.ConfigureCards(store, cardReader{a})
	if err := n.ReconcileCards(context.Background()); err == nil {
		t.Fatal("failed card update was not reported")
	}
	if store.closed[id] || store.retries != 1 {
		t.Fatal("failed update was lost")
	}
	fail = false
	restarted, _ := New(Config{URL: server.URL})
	restarted.ConfigureCards(store, cardReader{a})
	if err := restarted.ReconcileCards(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !store.closed[id] || calls != 2 {
		t.Fatal("restart did not retry the saved message")
	}
}

func TestExpiredUnconfirmedDeliveryDoesNotSendOutsideDeduplicationWindow(t *testing.T) {
	store := newMemoryCardStore()
	id := uuid.NewString()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(500) }))
	defer server.Close()
	store.cards[id] = domain.NotificationCard{EventID: id, WorkerURL: server.URL, AppealID: "appeal", ApprovalIDs: []string{"approval-1"}, DeliveryDeadline: time.Now().Add(-time.Minute)}
	n, _ := New(Config{URL: server.URL})
	n.ConfigureCards(store, cardReader{trackedAppeal("approved")})
	if err := n.ReconcileCards(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 0 || !store.closed[id] {
		t.Fatal("expired unknown delivery was replayed as a new message")
	}
}

func TestLayoutUpgradeRefreshesActiveCardOnce(t *testing.T) {
	store := newMemoryCardStore()
	a := trackedAppeal("pending")
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"message_id": "om_existing", "state_hash": domain.NotificationCardStateHash(a, []string{"approval-1"}, "b@example.com"), "terminal": false})
	}))
	defer server.Close()
	id := uuid.NewString()
	store.cards[id] = domain.NotificationCard{EventID: id, WorkerURL: server.URL, MessageID: "om_existing", AppealID: a.ID, Revision: 2, Recipient: "b@example.com", ApprovalIDs: []string{"approval-1"}, LastStateHash: "c1f754b1662d398cb805cf821be1359fe358dccf1b3fa0de288c8257da6981b1"}
	n, _ := New(Config{URL: server.URL})
	n.ConfigureCards(store, cardReader{a})
	if err := n.ReconcileCards(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := n.ReconcileCards(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("layout upgrade patched %d times, expected once", calls)
	}
}

func TestDay13CardReceivesFinalExpiryUpdateWithoutReplacement(t *testing.T) {
	store := newMemoryCardStore()
	a := trackedAppeal("pending")
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/cards/refresh" {
			t.Error("expiry sent a replacement notification")
		}
		calls++
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"message_id": "om_expiring", "state_hash": domain.NotificationCardStateHash(a, []string{"approval-1"}, "b@example.com"), "terminal": true})
	}))
	defer server.Close()
	id := uuid.NewString()
	store.cards[id] = domain.NotificationCard{EventID: id, WorkerURL: server.URL, MessageID: "om_expiring", AppealID: a.ID, Revision: 2, Recipient: "b@example.com", ApprovalIDs: []string{"approval-1"}, LastStateHash: domain.PendingNotificationCardHash(2, []string{"approval-1"}, "b@example.com"), CreatedAt: time.Now().Add(-13*24*time.Hour - time.Minute)}
	n, _ := New(Config{URL: server.URL})
	n.ConfigureCards(store, cardReader{a})
	if err := n.ReconcileCards(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := n.ReconcileCards(context.Background()); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	closed := store.closed[id]
	store.mu.Unlock()
	if !closed || calls != 1 {
		t.Fatal("day13 card did not receive exactly one final edit")
	}
	if len(store.cards) != 1 {
		t.Fatal("expiry created a replacement receipt")
	}
}

func (s *memoryCardStore) Ensure(ctx context.Context, c domain.NotificationCard, lease time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, v := range s.cards {
		if v.WorkerURL != c.WorkerURL || v.AppealID != c.AppealID || v.Revision != c.Revision || v.Recipient != c.Recipient {
			continue
		}
		if s.closed[id] || v.Expired(time.Now()) {
			return false, nil
		}
		seen := map[string]bool{}
		for _, id := range v.ApprovalIDs {
			seen[id] = true
		}
		changed := false
		for _, id := range c.ApprovalIDs {
			if !seen[id] {
				v.ApprovalIDs = append(v.ApprovalIDs, id)
				seen[id] = true
				changed = true
			}
		}
		if changed {
			v.LastStateHash = ""
			v.LeaseOwner = ""
			s.cards[id] = v
		}
		return false, nil
	}
	c.CreatedAt = time.Now()
	c.DeliveryDeadline = c.CreatedAt.Add(55 * time.Minute)
	s.cards[c.EventID] = c
	return true, nil
}

func TestSequentialStagesReuseMessageAfterNotifierRestart(t *testing.T) {
	store := newMemoryCardStore()
	a := trackedAppeal("pending")
	a.Revision = 1
	a.Approvals[0].AppealRevision = 1
	sends, updates := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/notifications" {
			sends++
			var e envelope
			_ = json.NewDecoder(r.Body).Decode(&e)
			_ = json.NewEncoder(w).Encode(map[string]string{"event_id": e.EventID, "message_id": "om_original", "bot": "pending"})
			return
		}
		updates++
		var q struct {
			MessageID   string   `json:"message_id"`
			ApprovalIDs []string `json:"approval_ids"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		if q.MessageID != "om_original" || len(q.ApprovalIDs) != 2 {
			t.Error("stage transition did not reuse original message/scope")
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"message_id": q.MessageID, "state_hash": domain.NotificationCardStateHash(a, q.ApprovalIDs, "b@example.com"), "terminal": false})
	}))
	defer server.Close()
	n, _ := New(Config{URL: server.URL})
	n.ConfigureCards(store, cardReader{a})
	if e := n.Notify(context.Background(), []domain.Notification{approvalItem("appeal", "approval-1", "Package admin", "b@example.com")}); len(e) > 0 {
		t.Fatal(e)
	}
	var original domain.NotificationCard
	for _, c := range store.cards {
		original = c
	}
	a.Approvals[0].Status = "approved"
	a.Approvals = append(a.Approvals, &domain.Approval{ID: "approval-2", Name: "Manager", Status: "pending", AppealRevision: 1, Approvers: []string{"b@example.com"}})
	n, _ = New(Config{URL: server.URL})
	n.ConfigureCards(store, cardReader{a})
	if e := n.Notify(context.Background(), []domain.Notification{approvalItem("appeal", "approval-2", "Manager", "b@example.com")}); len(e) > 0 {
		t.Fatal(e)
	}
	if err := n.ReconcileCards(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sends != 1 || updates != 1 || len(store.cards) != 1 || !store.cards[original.EventID].CreatedAt.Equal(original.CreatedAt) {
		t.Fatal("new stage created another message or reset age")
	}
	// A repeated notification does not repaint a user's form or send a duplicate.
	if e := n.Notify(context.Background(), []domain.Notification{approvalItem("appeal", "approval-2", "Manager", "b@example.com")}); len(e) > 0 {
		t.Fatal(e)
	}
	if err := n.ReconcileCards(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sends != 1 || updates != 1 {
		t.Fatal("unchanged notification repainted/resend")
	}
	c := store.cards[original.EventID]
	c.CreatedAt = time.Now().Add(-13 * 24 * time.Hour)
	store.cards[original.EventID] = c
	if e := n.Notify(context.Background(), []domain.Notification{approvalItem("appeal", "approval-3", "Later", "b@example.com")}); len(e) > 0 {
		t.Fatal(e)
	}
	if sends != 1 || len(store.cards[c.EventID].ApprovalIDs) != 2 {
		t.Fatal("expired card was replaced or expanded")
	}
}
