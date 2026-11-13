package domain

import "errors"

// NotificationSkippedError is an expected non-delivery, not a successful send
// and not a failed business operation. Callers must not retry this delivery.
// Codes are stable across the worker/notifier/job boundary; no upstream text or
// recipient data belongs in the error.
type NotificationSkippedError struct{ Code string }

const (
	NotificationRecipientNotResolved = "recipient_not_resolved"
	NotificationAppealObsolete       = "appeal_obsolete"
)

func (e *NotificationSkippedError) Error() string {
	switch e.Code {
	case NotificationRecipientNotResolved, NotificationAppealObsolete:
		return "notification skipped: " + e.Code
	default:
		return "unrecognized notification disposition"
	}
}

// NotificationSkipCode deliberately rejects unknown reasons and ordinary errors
// with matching text, so configuration/API failures cannot be silently skipped.
func NotificationSkipCode(err error) (string, bool) {
	var skipped *NotificationSkippedError
	if errors.As(err, &skipped) && skipped != nil {
		switch skipped.Code {
		case NotificationRecipientNotResolved, NotificationAppealObsolete:
			return skipped.Code, true
		}
	}
	return "", false
}
