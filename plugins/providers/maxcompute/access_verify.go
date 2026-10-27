package maxcompute

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var ErrAccessUnconfirmed = errors.New("MaxCompute access change not confirmed")

// AccessVerificationError describes readback, not whether the remote write
// failed. A timed-out operation may still complete later.
type AccessVerificationError struct {
	Operation  string
	Resource   string
	Unresolved []string
	Attempts   int
	Cause      error
}

func (e *AccessVerificationError) Error() string {
	return fmt.Sprintf("%s: operation=%s resource=%q unresolved=%v attempts=%d", ErrAccessUnconfirmed, e.Operation, e.Resource, e.Unresolved, e.Attempts)
}
func (e *AccessVerificationError) Unwrap() []error { return []error{ErrAccessUnconfirmed, e.Cause} }

type accessReadFn func(context.Context) (map[string]bool, error)

func verifyAccess(ctx context.Context, timeout time.Duration, operation, urn string, expected []string, present bool, read accessReadFn) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return pollAccess(ctx, operation, urn, expected, present, read, waitAccessRetry)
}

// Inject the wait in tests so convergence schedules need no real sleeps.
func pollAccess(ctx context.Context, operation, urn string, expected []string, present bool, read accessReadFn, wait func(context.Context, time.Duration) error) (int, error) {
	attempts := 0
	unresolved := append([]string(nil), expected...)
	var lastReadErr error
	failure := func(cause error) (int, error) {
		return attempts, &AccessVerificationError{Operation: operation, Resource: urn, Unresolved: unresolved, Attempts: attempts, Cause: errors.Join(cause, lastReadErr)}
	}
	delay := time.Second
	for {
		if err := ctx.Err(); err != nil {
			return failure(err)
		}
		attempts++
		state, err := read(ctx)
		if err == nil && state == nil {
			err = fmt.Errorf("%w: nil access state", errInvalidAccessResponse)
		}
		if err != nil {
			lastReadErr = err
			// The previous snapshot cannot establish absence when the current read
			// is incomplete. Every expected permission is unresolved on a read error.
			unresolved = append([]string(nil), expected...)
			if errors.Is(err, errInvalidAccessResponse) {
				return failure(err)
			}
		} else {
			unresolved = nil
			for _, permission := range expected {
				if state[permission] != present {
					unresolved = append(unresolved, permission)
				}
			}
			if err := ctx.Err(); err != nil {
				return failure(err)
			}
			if len(unresolved) == 0 {
				return attempts, nil
			}
		}
		if err := wait(ctx, delay); err != nil {
			return failure(err)
		}
		delay *= 2
		if delay > 5*time.Second {
			delay = 5 * time.Second
		}
	}
}
