package appeal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
)

func TestPostHookRetainsDetachedExecutionAndStableIdentity(t *testing.T) {
	var keys []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keys = append(keys, r.Header.Get("X-Guardian-Operation-ID"))
		w.WriteHeader(200)
	}))
	defer srv.Close()
	s := &Service{logger: log.NewNoop()}
	a := &domain.Appeal{ID: "appeal", Revision: 2}
	hooks := []*domain.PostAppealHook{{Name: "create_package", Type: "http", Config: map[string]interface{}{"url": strconv.Quote(srv.URL), "method": "POST"}}}
	for i := 0; i < 2; i++ {
		if err := s.executePostAppealHooks(context.Background(), hooks, a, nil, &domain.Requirement{}, &domain.Policy{}); err != nil {
			t.Fatal(err)
		}
	}
	if len(keys) != 2 || len(keys[0]) != 64 || keys[0] != keys[1] {
		t.Fatal("hook retry identity changed")
	}
	c, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.executePostAppealHooks(c, hooks, a, nil, &domain.Requirement{}, &domain.Policy{}); err != nil {
		t.Fatal("existing detached hook behavior changed", err)
	}
	if len(keys) != 3 {
		t.Fatal("detached hook did not finish")
	}

}

func TestRequirementsHookDoesNotUseFinishedErrgroupContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	s := &Service{logger: log.NewNoop()}
	a := &domain.Appeal{ID: "appeal", Revision: 2}
	p := &domain.Policy{Requirements: []*domain.Requirement{{On: &domain.RequirementTrigger{Expression: "true"}, PostHooks: []*domain.PostAppealHook{{Name: "create_package", Type: "http", Config: map[string]interface{}{"url": strconv.Quote(srv.URL), "method": "POST"}}}}}}
	if err := s.handleAppealRequirements(context.Background(), a, p); err != nil {
		t.Fatal("healthy post-hook canceled after empty dependency group", err)
	}
}

func TestDetachedPostHookHasFiniteLifetime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer srv.Close()
	s := &Service{logger: log.NewNoop(), postHookTimeout: 50 * time.Millisecond}
	hooks := []*domain.PostAppealHook{{Name: "slow", Type: "http", Config: map[string]interface{}{"url": strconv.Quote(srv.URL), "method": "POST"}}}
	started := time.Now()
	if err := s.executePostAppealHooks(context.Background(), hooks, &domain.Appeal{ID: "appeal"}, nil, &domain.Requirement{}, &domain.Policy{}); err == nil {
		t.Fatal("unresponsive hook did not time out")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("hook exceeded configured budget")
	}
}
