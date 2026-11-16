package larkv2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/goto/guardian/domain"
)

func TestUnresolvedInitialDeliveryClosesReceiptAndContinuesBatch(t *testing.T) {
	store := newMemoryCardStore()
	a := trackedAppeal("pending")
	a.Revision = 1
	counts := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var e envelope
		_ = json.NewDecoder(r.Body).Decode(&e)
		counts[e.Recipient]++
		if e.Recipient == "missing@example.com" {
			w.WriteHeader(422)
			_, _ = w.Write([]byte(`{"error":"recipient_not_resolved"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"event_id": e.EventID, "message_id": "om_valid", "bot": "pending"})
	}))
	defer server.Close()
	n, _ := New(Config{URL: server.URL})
	n.ConfigureCards(store, cardReader{a})
	items := []domain.Notification{approvalItem(a.ID, "approval-1", "Owner", "missing@example.com"), approvalItem(a.ID, "approval-1", "Owner", "b@example.com")}
	errs := n.Notify(context.Background(), items)
	if len(errs) != 1 {
		t.Fatalf("expected one skipped disposition: %v", errs)
	}
	if code, ok := domain.NotificationSkipCode(errs[0]); !ok || code != domain.NotificationRecipientNotResolved {
		t.Fatal("expected typed skip")
	}
	var skippedID string
	for id, card := range store.cards {
		if card.Recipient == "missing@example.com" {
			skippedID = id
		}
	}
	if skippedID == "" || !store.closed[skippedID] || store.cards[skippedID].MessageID != "" {
		t.Fatal("skip must persist without inventing a sent message")
	}
	if counts["missing@example.com"] != 1 || counts["b@example.com"] != 1 {
		t.Fatal("skip retried or prevented another recipient")
	}
	// A new notifier instance and a later approval stage must not reopen the skip.
	restarted, _ := New(Config{URL: server.URL})
	restarted.ConfigureCards(store, cardReader{a})
	if errs := restarted.Notify(context.Background(), []domain.Notification{approvalItem(a.ID, "approval-2", "Next", "missing@example.com")}); len(errs) != 0 {
		t.Fatal(errs)
	}
	if counts["missing@example.com"] != 1 || !store.closed[skippedID] {
		t.Fatal("restart reopened a permanently skipped delivery")
	}
}

func TestUndeliveredRecoveryDispositions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		skipped bool
	}{
		{"unresolved", 422, `{"error":"recipient_not_resolved"}`, true},
		{"legacy_422", 422, `{"error":"delivery_failed"}`, false},
		{"malformed", 422, `not-json`, false},
		{"rate_limit", 429, `{"error":"recipient_not_resolved"}`, false},
		{"temporary", 503, `{"error":"recipient_not_resolved"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			store := newMemoryCardStore()
			id := uuid.NewString()
			a := trackedAppeal("pending")
			store.cards[id] = domain.NotificationCard{EventID: id, WorkerURL: server.URL, AppealID: a.ID, Revision: 2, Recipient: "b@example.com", ApprovalIDs: []string{"approval-1"}, DeliveryDeadline: time.Now().Add(time.Hour)}
			n, _ := New(Config{URL: server.URL})
			n.ConfigureCards(store, cardReader{a})
			for i := 0; i < 2; i++ {
				err := n.ReconcileCards(context.Background())
				if (err == nil) != tc.skipped {
					t.Fatalf("unexpected reconcile result: %v", err)
				}
			}
			wantCalls := 2
			if tc.skipped {
				wantCalls = 1
			}
			if calls != wantCalls || store.closed[id] != tc.skipped {
				t.Fatalf("calls=%d closed=%v", calls, store.closed[id])
			}
		})
	}
}

func TestObsoleteUndeliveredCardsNeverSend(t *testing.T) {
	for _, status := range []string{"approved", "rejected", "cancelled", "stale_revision"} {
		t.Run(status, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(503) }))
			defer server.Close()
			a := trackedAppeal(status)
			a.Revision = 1
			if status == "stale_revision" {
				a.Status = "pending"
				a.Revision = 2
			}
			store := newMemoryCardStore()
			n, _ := New(Config{URL: server.URL})
			n.ConfigureCards(store, cardReader{a})
			errs := n.Notify(context.Background(), []domain.Notification{approvalItem(a.ID, "approval-1", "Owner", "b@example.com")})
			if len(errs) != 1 {
				t.Fatalf("expected obsolete disposition: %v", errs)
			}
			if code, ok := domain.NotificationSkipCode(errs[0]); !ok || code != domain.NotificationAppealObsolete {
				t.Fatal("wrong obsolete disposition")
			}
			// Seed a pre-existing pending receipt to verify reconciliation as well.
			id := uuid.NewString()
			store.cards[id] = domain.NotificationCard{EventID: id, WorkerURL: server.URL, AppealID: a.ID, Revision: 1, Recipient: "a@example.com", ApprovalIDs: []string{"approval-1"}, DeliveryDeadline: time.Now().Add(time.Hour)}
			if err := n.ReconcileCards(context.Background()); err != nil {
				t.Fatal(err)
			}
			if calls != 0 || !store.closed[id] {
				t.Fatal("obsolete approval prompt was delivered")
			}
		})
	}
}

type failingSkipStore struct{ *memoryCardStore }

func (s failingSkipStore) Complete(context.Context, domain.NotificationCard, string, bool, time.Duration) error {
	return errors.New("synthetic database failure")
}

func TestSkipPersistenceFailureIsNotSwallowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(422)
		_, _ = w.Write([]byte(`{"error":"recipient_not_resolved"}`))
	}))
	defer server.Close()
	store := failingSkipStore{newMemoryCardStore()}
	a := trackedAppeal("pending")
	a.Revision = 1
	n, _ := New(Config{URL: server.URL})
	n.ConfigureCards(store, cardReader{a})
	errs := n.Notify(context.Background(), []domain.Notification{approvalItem(a.ID, "approval-1", "Owner", "missing@example.com")})
	if len(errs) != 1 {
		t.Fatal("missing persistence error")
	}
	if _, skip := domain.NotificationSkipCode(errs[0]); skip {
		t.Fatal("database failure classified as skip")
	}
	for id := range store.cards {
		if store.closed[id] {
			t.Fatal("failed persistence closed receipt")
		}
	}
}

type finishingAppealReader struct{ reads int }

func (r *finishingAppealReader) GetByID(context.Context, string) (*domain.Appeal, error) {
	r.reads++
	a := trackedAppeal("pending")
	a.Revision = 1
	if r.reads > 1 {
		a.Status = domain.AppealStatusApproved
	}
	return a, nil
}

func TestAppealFinishingBetweenImmediateRetriesStopsDelivery(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(503) }))
	defer server.Close()
	store := newMemoryCardStore()
	n, _ := New(Config{URL: server.URL})
	n.ConfigureCards(store, &finishingAppealReader{})
	n.delays = []time.Duration{0, 0}
	errs := n.Notify(context.Background(), []domain.Notification{approvalItem("appeal", "approval-1", "Owner", "b@example.com")})
	if len(errs) != 1 || calls != 1 {
		t.Fatalf("obsolete retry sent: calls=%d errors=%v", calls, errs)
	}
	if code, ok := domain.NotificationSkipCode(errs[0]); !ok || code != domain.NotificationAppealObsolete {
		t.Fatal("expected obsolete skip")
	}
	for id := range store.cards {
		if !store.closed[id] {
			t.Fatal("obsolete delivery not closed")
		}
	}
}

func TestUntrackedNotificationPropagatesSkipWithoutBlockingOtherRecipients(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var e envelope
		_ = json.NewDecoder(r.Body).Decode(&e)
		if e.Recipient == "missing@example.com" {
			w.WriteHeader(422)
			_, _ = w.Write([]byte(`{"error":"recipient_not_resolved"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"event_id": e.EventID, "message_id": "om_general", "bot": "notification"})
	}))
	defer server.Close()
	n, _ := New(Config{URL: server.URL})
	errs := n.Notify(context.Background(), []domain.Notification{
		{User: "missing@example.com", Message: domain.NotificationMessage{Type: domain.NotificationTypeExpirationReminder}},
		{User: "valid@example.com", Message: domain.NotificationMessage{Type: domain.NotificationTypeExpirationReminder}},
	})
	if calls != 2 || len(errs) != 1 {
		t.Fatalf("general batch interrupted or retried: %d %v", calls, errs)
	}
	if code, ok := domain.NotificationSkipCode(errs[0]); !ok || code != domain.NotificationRecipientNotResolved {
		t.Fatal("job caller lost typed skip")
	}
}
