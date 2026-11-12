package larkv2

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goto/guardian/domain"
)

func TestNotificationContractAndRetryIdentity(t *testing.T) {
	calls := 0
	eventID := ""
	var first []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v1/notifications" || r.Header.Get("Authorization") != "" {
			t.Error("wrong private endpoint or unexpected authorization header")
		}
		body, _ := io.ReadAll(r.Body)
		var value envelope
		_ = json.Unmarshal(body, &value)
		if value.Type != "ApproverNotification" || value.Recipient != "approver@example.com" || value.Approval == nil || value.Approval.ApprovalID != "approval-id" || value.Approval.Revision != 2 {
			t.Error("incorrect wire contract")
		}
		if calls == 1 {
			eventID = value.EventID
			first = body
			w.WriteHeader(503)
			return
		}
		if eventID == "" || eventID != value.EventID || string(first) != string(body) {
			t.Error("retry changed payload or event ID")
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"event_id": value.EventID, "message_id": "om_message", "bot": "pending"})
	}))
	defer server.Close()
	n, err := New(Config{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	n.delays = []time.Duration{0, 0}
	errs := n.Notify(context.Background(), []domain.Notification{{User: "approver@example.com", Message: domain.NotificationMessage{Type: domain.NotificationTypeApproverNotification, Variables: map[string]interface{}{"duration": "24 hours"}}, Approval: &domain.NotificationApproval{AppealID: "appeal-id", ApprovalID: "approval-id", Revision: 2}}})
	if len(errs) != 0 || calls != 2 {
		t.Fatalf("delivery: %v; calls %d", errs, calls)
	}
}

func TestPermanentFailuresDoNotRetryOrLeakBody(t *testing.T) {
	for _, status := range []int{400, 401, 422, 302} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Location", "https://example.com/private")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "private-response")
			}))
			defer server.Close()
			n, _ := New(Config{URL: server.URL})
			n.delays = []time.Duration{0, 0}
			errs := n.Notify(context.Background(), []domain.Notification{{User: "person@example.com", Message: domain.NotificationMessage{Type: domain.NotificationTypeAppealApproved}}})
			if len(errs) != 1 || calls != 1 {
				t.Fatal("permanent failure retried")
			}
			if strings.Contains(errs[0].Error(), "private-response") || strings.Contains(errs[0].Error(), server.URL) {
				t.Fatal("private response leaked")
			}
		})
	}
}

func TestTransientFailuresAreBounded(t *testing.T) {
	for _, status := range []int{429, 502} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(status) }))
			defer server.Close()
			n, _ := New(Config{URL: server.URL})
			n.delays = []time.Duration{0, 0}
			errs := n.Notify(context.Background(), []domain.Notification{{User: "person@example.com", Message: domain.NotificationMessage{Type: domain.NotificationTypeAppealApproved}}})
			if len(errs) != 1 || calls != 3 {
				t.Fatalf("wrong retry bound: %d", calls)
			}
		})
	}
}

func TestLarkV2ConfigurationAndMissingApprovalContext(t *testing.T) {
	for _, cfg := range []Config{{}, {URL: "https://user:private@example.com"}, {URL: "https://example.com/api"}, {URL: "https://example.com", TimeoutSeconds: 1}} {
		if _, err := New(cfg); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	n, _ := New(Config{URL: "https://example.com"})
	errs := n.Notify(context.Background(), []domain.Notification{{User: "person@example.com", Message: domain.NotificationMessage{Type: domain.NotificationTypeApproverNotification}}})
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "exact approval context") {
		t.Fatal("missing approval identity accepted")
	}
}
