package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

type cardLookupStub struct {
	card  *domain.NotificationCard
	err   error
	calls int
}

func (s *cardLookupStub) GetByMessageID(context.Context, string) (*domain.NotificationCard, error) {
	s.calls++
	return s.card, s.err
}

func TestNotificationCardLookupUsesGuardianIdentityAndRecipient(t *testing.T) {
	for _, test := range []struct {
		name, actor string
		lookupErr   error
		status      int
	}{
		{"recipient", "APPROVER@example.com", nil, 200},
		{"missing actor", "", nil, 401},
		{"other recipient", "someone@example.com", nil, 404},
		{"missing receipt", "approver@example.com", gorm.ErrRecordNotFound, 404},
		{"database error", "approver@example.com", errors.New("private database detail"), 503},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := &Config{}
			config.Auth.Default.HeaderKey = "X-Verified-Email"
			mux := runtime.NewServeMux(runtime.WithIncomingHeaderMatcher(makeHeaderMatcher(config)))
			store := &cardLookupStub{card: &domain.NotificationCard{MessageID: "om_test", AppealID: "appeal", Revision: 2, Recipient: "approver@example.com", ApprovalIDs: []string{"step-b", "step-c"}}, err: test.lookupErr}
			if err := registerNotificationCardLookup(mux, headerAuthInterceptor(config.Auth.Default.HeaderKey), authenticatedUserEmailContextKey{}, store); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodGet, "/v1beta1/notification-cards/om_test", nil)
			if test.actor != "" {
				r.Header.Set(config.Auth.Default.HeaderKey, test.actor)
			}
			// An unrelated header cannot stand in for the configured identity.
			r.Header.Set("X-Auth-Email", "approver@example.com")
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != test.status {
				t.Fatalf("got %d: %s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "private database detail") {
				t.Fatal("database error leaked")
			}
			if w.Code == 200 && !strings.Contains(w.Body.String(), `"approval_ids":["step-b","step-c"]`) {
				t.Fatal("stored scope missing")
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("receipt response can be cached")
			}
		})
	}
}

func TestNotificationCardLookupHonorsAuthInterceptorRejection(t *testing.T) {
	mux := runtime.NewServeMux()
	store := &cardLookupStub{}
	deny := func(context.Context, interface{}, *grpc.UnaryServerInfo, grpc.UnaryHandler) (interface{}, error) {
		return nil, status.Error(codes.Unauthenticated, "invalid identity")
	}
	if err := registerNotificationCardLookup(mux, deny, authenticatedUserEmailContextKey{}, store); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/v1beta1/notification-cards/om_test", nil)
	r.Header.Set("X-Auth-Email", "approver@example.com")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 401 || store.calls != 0 {
		t.Fatal("authentication rejection bypassed")
	}
}

type planReaderStub struct{ a *domain.Appeal }

func (r planReaderStub) GetByID(context.Context, string) (*domain.Appeal, error) { return r.a, nil }
func TestReceiptLookupReturnsOnlyBoundedEligibleSequence(t *testing.T) {
	config := &Config{}
	config.Auth.Default.HeaderKey = "X-Verified-Email"
	mux := runtime.NewServeMux(runtime.WithIncomingHeaderMatcher(makeHeaderMatcher(config)))
	store := &cardLookupStub{card: &domain.NotificationCard{MessageID: "om_test", AppealID: "appeal", Revision: 2, Recipient: "a@example.com", ApprovalIDs: []string{"p", "m"}}}
	appeal := &domain.Appeal{ID: "appeal", Status: "pending", Revision: 2, Approvals: []*domain.Approval{{ID: "p", Name: "Package", Index: 0, Status: "pending", AppealRevision: 2, Approvers: []string{"a@example.com"}}, {ID: "m", Name: "Manager", Index: 1, Status: "blocked", AppealRevision: 2, Approvers: []string{"a@example.com"}}, {ID: "l", Name: "Lead", Index: 2, Status: "blocked", AppealRevision: 2, Approvers: []string{"a@example.com"}}}}
	if err := registerNotificationCardLookup(mux, headerAuthInterceptor(config.Auth.Default.HeaderKey), authenticatedUserEmailContextKey{}, store, planReaderStub{appeal}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/v1beta1/notification-cards/om_test", nil)
	r.Header.Set("X-Verified-Email", "a@example.com")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	var result struct {
		Card struct {
			Plan []domain.NotificationApprovalStep `json:"approval_plan"`
		} `json:"card"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || len(result.Card.Plan) != 2 || result.Card.Plan[1].Status != "blocked" {
		t.Fatalf("bad bounded plan: %d %s", w.Code, w.Body.String())
	}
}
