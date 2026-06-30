package alertmanager_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/plugins/notifiers/alertmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSirenClient_Send(t *testing.T) {
	validEvent := alertmanager.Event{
		Title:    alertmanager.GrantDriftCheckEvent,
		Data:     map[string]interface{}{"key": "value"},
		Team:     "test-team",
		Severity: "critical",
	}

	t.Run("sends correct JSON payload to siren endpoint", func(t *testing.T) {
		var gotBody []byte
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			gotBody, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{
				"notification_id": "cbc33678-a768-4a9a-aaff-fb163e2e5c6f",
			})
		}))
		defer srv.Close()

		client := alertmanager.NewSirenClient(srv.URL, "production")
		logger := log.NewNoop()
		err := client.Send(context.Background(), validEvent, logger)

		require.NoError(t, err)

		var payload map[string]interface{}
		require.NoError(t, json.Unmarshal(gotBody, &payload))
		assert.Equal(t, "guardian-grant-drift-check", payload["template"])
		labels, ok := payload["labels"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "critical", labels["severity"])
		assert.Equal(t, "production", labels["environment"])
		assert.Equal(t, "test-team", labels["team"])
	})

	t.Run("returns error for unmapped event title", func(t *testing.T) {
		client := alertmanager.NewSirenClient("http://unused", "production")
		logger := log.NewNoop()
		err := client.Send(context.Background(), alertmanager.Event{Title: "unknown-event"}, logger)
		assert.EqualError(t, err, "no siren template mapped for event title: unknown-event")
	})

	t.Run("returns error when server is unreachable", func(t *testing.T) {
		client := alertmanager.NewSirenClient("http://127.0.0.1:0", "production")
		logger := log.NewNoop()
		err := client.Send(context.Background(), validEvent, logger)
		assert.Error(t, err)
	})

	t.Run("returns error on non-200 response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "bad request", http.StatusBadRequest)
		}))
		defer srv.Close()

		client := alertmanager.NewSirenClient(srv.URL, "production")
		logger := log.NewNoop()
		err := client.Send(context.Background(), validEvent, logger)
		assert.ErrorContains(t, err, "siren returned non-200 status")
	})
}
