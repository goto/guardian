package notifiers

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
)

type deliveryLogger struct {
	log.Logger
	warns, errors int
}

func (l *deliveryLogger) Warn(context.Context, string, ...interface{})  { l.warns++ }
func (l *deliveryLogger) Error(context.Context, string, ...interface{}) { l.errors++ }

func TestTypedSkipsWarnAndOtherFailuresRemainErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		skip bool
	}{
		{&domain.NotificationSkippedError{Code: domain.NotificationRecipientNotResolved}, true},
		{fmt.Errorf("wrapped: %w", &domain.NotificationSkippedError{Code: domain.NotificationAppealObsolete}), true},
		{&domain.NotificationSkippedError{Code: "unknown"}, false},
		{errors.New("recipient_not_resolved"), false},
		{errors.New("temporary transport error"), false},
	} {
		l := &deliveryLogger{Logger: log.NewNoop()}
		LogDeliveryError(context.Background(), l, tc.err)
		if (l.warns == 1) != tc.skip || (l.errors == 1) == tc.skip {
			t.Fatalf("wrong severity for %T: warns=%d errors=%d", tc.err, l.warns, l.errors)
		}
	}
}
