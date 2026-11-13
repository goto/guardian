package notifiers

import (
	"context"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
)

// LogDeliveryError keeps expected skips visible without treating them as job or
// approval failures. The original error behavior remains for all other failures.
func LogDeliveryError(ctx context.Context, logger log.Logger, err error, fields ...interface{}) {
	if err == nil || logger == nil {
		return
	}
	if code, skipped := domain.NotificationSkipCode(err); skipped {
		logger.Warn(ctx, "notification delivery skipped", append(fields, "code", code, "retryable", false)...)
		return
	}
	logger.Error(ctx, "failed to send notifications", append(fields, "error", err.Error())...)
}
