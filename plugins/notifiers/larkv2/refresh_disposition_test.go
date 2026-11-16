package larkv2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goto/guardian/domain"
)

func TestDeliveredRefreshDispositionsSurviveRestart(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		skip   bool
	}{
		{"unresolved", 422, `{"error":"recipient_not_resolved"}`, true},
		{"generic", 422, `{"error":"card_refresh_failed"}`, false},
		{"malformed", 422, `not-json`, false},
		{"trailing", 422, `{"error":"recipient_not_resolved"}garbage`, false},
		{"rate_limit", 429, `{"error":"recipient_not_resolved"}`, false},
		{"temporary", 502, `{"error":"recipient_not_resolved"}`, false},
		{"other_client_error", 400, `{"error":"recipient_not_resolved"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/cards/refresh" {
					t.Error("unexpected new delivery")
				}
				atomic.AddInt32(&calls, 1)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			store := newMemoryCardStore()
			a := trackedAppeal("pending")
			card := domain.NotificationCard{EventID: "event", WorkerURL: server.URL, MessageID: "om_existing", AppealID: a.ID, Revision: 2, Recipient: "b@example.com", ApprovalIDs: []string{"approval-1"}, LastStateHash: "previous-hash", DeliveryDeadline: time.Now().Add(time.Hour)}
			store.cards[card.EventID] = card
			for i := 0; i < 2; i++ {
				// Recreate the notifier while retaining durable receipt state.
				n, _ := New(Config{URL: server.URL})
				n.ConfigureCards(store, cardReader{a})
				err := n.ReconcileCards(context.Background())
				if (err == nil) != tc.skip {
					t.Fatalf("unexpected outcome: %v", err)
				}
				if err != nil && !strings.Contains(err.Error(), "failed=1 claimed=1") {
					t.Fatal("missing safe batch diagnostics")
				}
			}
			want := int32(2)
			if tc.skip {
				want = 1
			}
			if calls != want || store.closed[card.EventID] != tc.skip {
				t.Fatalf("calls=%d closed=%v", calls, store.closed[card.EventID])
			}
			if store.cards[card.EventID].MessageID != card.MessageID || store.cards[card.EventID].LastStateHash != card.LastStateHash || a.Status != "pending" {
				t.Fatal("skip fabricated update or changed appeal")
			}
			if tc.skip {
				n, _ := New(Config{URL: server.URL})
				n.ConfigureCards(store, cardReader{a})
				item := approvalItem(a.ID, "approval-2", "Next", "b@example.com")
				item.Approval.Revision = 2
				if errs := n.Notify(context.Background(), []domain.Notification{item}); len(errs) != 0 {
					t.Fatal(errs)
				}
				if calls != 1 {
					t.Fatal("later stage reopened receipt")
				}
			}
		})
	}
}

func TestRefreshSkipPersistenceFailureAndTemporaryRecovery(t *testing.T) {
	for _, persistenceFailure := range []bool{false, true} {
		store := newMemoryCardStore()
		a := trackedAppeal("pending")
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if persistenceFailure {
				w.WriteHeader(422)
				_, _ = w.Write([]byte(`{"error":"recipient_not_resolved"}`))
				return
			}
			if calls == 1 {
				w.WriteHeader(503)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"message_id": "om_existing", "state_hash": domain.NotificationCardStateHash(a, []string{"approval-1"}, "b@example.com"), "terminal": false})
		}))
		store.cards["event"] = domain.NotificationCard{EventID: "event", WorkerURL: server.URL, MessageID: "om_existing", AppealID: a.ID, Revision: 2, Recipient: "b@example.com", ApprovalIDs: []string{"approval-1"}, LastStateHash: "old"}
		n, _ := New(Config{URL: server.URL})
		if persistenceFailure {
			n.ConfigureCards(failingSkipStore{store}, cardReader{a})
		} else {
			n.ConfigureCards(store, cardReader{a})
		}
		if err := n.ReconcileCards(context.Background()); err == nil {
			t.Fatal("expected visible failure")
		}
		if store.closed["event"] || store.retries != 1 {
			t.Fatal("failure closed receipt or failed to release for retry")
		}
		err := n.ReconcileCards(context.Background())
		if (err != nil) != persistenceFailure {
			t.Fatalf("unexpected recovery: %v", err)
		}
		if !persistenceFailure {
			if err := n.ReconcileCards(context.Background()); err != nil {
				t.Fatal(err)
			}
			if calls != 2 {
				t.Fatal("unchanged recovered card repainted")
			}
		}
		server.Close()
	}
}
