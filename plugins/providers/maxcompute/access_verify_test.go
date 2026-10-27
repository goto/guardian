package maxcompute

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAccessVerificationConvergence(t *testing.T) {
	for _, present := range []bool{true, false} {
		t.Run(map[bool]string{true: "grant", false: "revoke"}[present], func(t *testing.T) {
			calls := 0
			var delays []time.Duration
			attempts, err := pollAccess(context.Background(), "change", "p.s.t", []string{"select", "update"}, present, func(context.Context) (map[string]bool, error) {
				calls++
				return map[string]bool{"select": present, "update": calls >= 3 == present}, nil
			}, func(_ context.Context, d time.Duration) error { delays = append(delays, d); return nil })
			require.NoError(t, err)
			require.Equal(t, 3, attempts)
			require.Equal(t, []time.Duration{time.Second, 2 * time.Second}, delays)
		})
	}
}

func TestAccessVerificationImmediateAndIncomplete(t *testing.T) {
	t.Run("immediate", func(t *testing.T) {
		n, err := pollAccess(context.Background(), "grant", "p", []string{"reader"}, true, func(context.Context) (map[string]bool, error) { return map[string]bool{"reader": true}, nil }, func(context.Context, time.Duration) error { t.Fatal("unexpected sleep"); return nil })
		require.NoError(t, err)
		require.Equal(t, 1, n)
	})
	for _, readErr := range []error{errors.New("throttled"), errors.New("permission denied"), errors.New("transport failure")} {
		t.Run(readErr.Error(), func(t *testing.T) {
			var delays []time.Duration
			n, err := pollAccess(context.Background(), "revoke", "p", []string{"reader"}, false, func(context.Context) (map[string]bool, error) { return map[string]bool{}, readErr }, func(_ context.Context, d time.Duration) error {
				delays = append(delays, d)
				if len(delays) == 5 {
					return context.DeadlineExceeded
				}
				return nil
			})
			require.ErrorIs(t, err, ErrAccessUnconfirmed)
			require.ErrorIs(t, err, readErr)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			require.Equal(t, 5, n)
			require.Equal(t, []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second}, delays)
		})
	}
	t.Run("unknown never means absent", func(t *testing.T) {
		_, err := pollAccess(context.Background(), "revoke", "p", []string{"reader"}, false, func(context.Context) (map[string]bool, error) { return nil, nil }, func(context.Context, time.Duration) error {
			t.Fatal("invalid response should fail immediately")
			return nil
		})
		require.ErrorIs(t, err, errInvalidAccessResponse)
	})
	t.Run("partial", func(t *testing.T) {
		_, err := pollAccess(context.Background(), "grant", "p", []string{"reader", "writer"}, true, func(context.Context) (map[string]bool, error) { return map[string]bool{"reader": true}, nil }, func(context.Context, time.Duration) error { return context.DeadlineExceeded })
		var verification *AccessVerificationError
		require.ErrorAs(t, err, &verification)
		require.Equal(t, []string{"writer"}, verification.Unresolved)
	})
}

func TestAccessVerificationDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n, err := verifyAccess(ctx, time.Second, "grant", "p", []string{"reader"}, true, func(context.Context) (map[string]bool, error) { t.Fatal("read after cancellation"); return nil, nil })
	require.Zero(t, n)
	require.ErrorIs(t, err, context.Canceled)
	start := time.Now()
	_, err = verifyAccess(context.Background(), 20*time.Millisecond, "grant", "p", []string{"reader"}, true, func(ctx context.Context) (map[string]bool, error) { <-ctx.Done(); return nil, ctx.Err() })
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), time.Second)
}

func TestTableAccessParsing(t *testing.T) {
	raw := `{"ACL":{"": [{"Action":["Select","ReadLowFrequencyStorage","ReadLongTermStorage"],"Effect":"","Principal":["user/RAM$1:2","user/RAM$1:role/team(acs:odps:*)"]},{"Action":["All"],"Effect":"Deny","Principal":["user/RAM$1:2"]}]},"POLICY":{"role/other":[{"Action":["All"]}]}}`
	entries, err := parseTableAccess(raw, "RAM$1:role/team")
	require.NoError(t, err)
	require.Len(t, entries, 3)
	for _, entry := range entries {
		require.Equal(t, accountTypeRAMRole, entry.AccountType)
		require.Equal(t, "RAM$1:role/team", entry.AccountID)
	}
	entries, err = parseTableAccess(raw, "RAM$1:2")
	require.NoError(t, err)
	require.Len(t, entries, 3)
	require.Equal(t, "SELECT", entries[0].Permission)
	entries, err = parseTableAccess(`{"ACL":{}}`)
	require.NoError(t, err)
	require.Empty(t, entries)
	for _, bad := range []string{`null`, `{}`, `bad`,
		`{"ACL":{"": [{"Action":["Select"],"Effect":"unknown","Principal":["user/RAM$1:2"]}]}}`,
		`{"ACL":{"": [{"Action":["Select"],"Principal":["user/RAM$1:2("]}]}}`, `{"ACL":{"": [{"Action":[],"Principal":["user/RAM$1:2"]}]}}`} {
		_, err := parseTableAccess(bad)
		require.ErrorIs(t, err, errInvalidAccessResponse)
	}
}

func TestVerificationTimeoutConfiguration(t *testing.T) {
	d, err := (credentials{}).verificationTimeout()
	require.NoError(t, err)
	require.Equal(t, 15*time.Second, d)
	for _, seconds := range []int{-1, 0, 7} {
		c := credentials{AccessVerificationTimeoutSeconds: &seconds}
		d, err := c.verificationTimeout()
		if seconds <= 0 {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.Equal(t, 7*time.Second, d)
		}
	}
	cfg := permissionConfig(resourceTypeTable, "select")
	cfg.Credentials = map[string]interface{}{"access_key_id": "test", "access_key_secret": "test", "region_id": "test", "project_name": "p", "access_verification_timeout_seconds": 3}
	creds, err := cfg.getCredentials()
	require.NoError(t, err)
	d, err = creds.verificationTimeout()
	require.NoError(t, err)
	require.Equal(t, 3*time.Second, d)
}
