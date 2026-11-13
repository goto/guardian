package jobs

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/pkg/log"
)

type failingResourceFetcher struct {
	providerService
	err error
}

func (s failingResourceFetcher) FetchResources(context.Context) error { return s.err }

func TestFetchJobOnlySkipsIndividualProviderFailures(t *testing.T) {
	for _, test := range []struct {
		name      string
		err       error
		wantError bool
	}{
		{"healthy", nil, false},
		{"stale provider", fmt.Errorf("%w: stale-project", provider.ErrPartialResourceSync), false},
		{"shared database unavailable", errors.New("cannot load providers"), true},
		{"canceled", context.Canceled, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := handler{providerService: failingResourceFetcher{err: test.err}, logger: log.NewNoop()}
			if err := h.FetchResources(context.Background(), nil); (err != nil) != test.wantError {
				t.Fatalf("got %v", err)
			}
		})
	}
}
