package alicatalogapis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	roleBindingConcurrentModification = "role bindings of this object have been modified"
	roleBindingUpdateMaxAttempts      = 3
	roleBindingRetryBaseDelay         = 50 * time.Millisecond
)

var errRoleBindingMarshal = errors.New("fail to marshal role binding policy")

// roleBindingMutateFn applies the caller's intent onto a freshly loaded policy.
// ETag from getPolicy must be left intact so setPolicy can enforce optimistic concurrency.
type roleBindingMutateFn func(binding *RoleBinding)

func isRoleBindingConcurrentModification(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), roleBindingConcurrentModification)
}

func isRoleBindingRoleMissing(err error) bool {
	return err != nil && strings.Contains(err.Error(), "role does not exists")
}

func waitForRoleBindingRetry(ctx context.Context, attempt int) error {
	timer := time.NewTimer(roleBindingRetryBaseDelay * time.Duration(1<<attempt))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// readModifyWriteRoleBinding loads policy, applies mutate, and setPolicy with bounded
// retries. Each attempt re-reads so the latest policy.etag is forwarded.
//
// Catalog bumps etag on every successful setPolicy, including content no-ops, so a stale
// etag after any concurrent writer (or even our own prior write) must not be reused.
func (c *client) readModifyWriteRoleBinding(
	ctx context.Context,
	getPolicy func(context.Context) (*RoleBinding, error),
	mutate roleBindingMutateFn,
	setPolicyPath string,
) (*RoleBindingPolicy, error) {
	params := url.Values{"principleFormat": []string{"id"}}
	var lastErr error
	for attempt := 0; attempt < roleBindingUpdateMaxAttempts; attempt++ {
		binding, err := getPolicy(ctx)
		if err != nil {
			return nil, err
		}
		mutate(binding)
		if binding.Policy == nil {
			binding.Policy = new(RoleBindingPolicy)
		}
		binding.Policy.toAliFormat(c.accountID)

		body, err := json.Marshal(binding)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errRoleBindingMarshal, err)
		}

		policy := new(RoleBindingPolicy)
		err = c.sendRequestAndUnmarshal(ctx, http.MethodPost, setPolicyPath, params, nil, body, http.StatusOK, policy)
		if err == nil {
			policy.toUserFormat()
			return policy, nil
		}
		lastErr = err
		if isRoleBindingRoleMissing(err) {
			return nil, err
		}
		if !isRoleBindingConcurrentModification(err) || attempt == roleBindingUpdateMaxAttempts-1 {
			return nil, err
		}
		if err := waitForRoleBindingRetry(ctx, attempt); err != nil {
			return nil, err
		}
	}
	return nil, lastErr
}
