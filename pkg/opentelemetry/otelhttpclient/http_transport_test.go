package otelhttpclient_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goto/guardian/pkg/opentelemetry/otelhttpclient"
	"github.com/stretchr/testify/assert"
)

func TestNewHTTPTransport(t *testing.T) {
	t.Run("should return new HTTP transport", func(t *testing.T) {
		tr := otelhttpclient.NewHTTPTransport(nil, "test")
		assert.NotNil(t, tr)
	})
	t.Run("should wrap existing HTTP transport", func(t *testing.T) {
		tr := otelhttpclient.NewHTTPTransport(http.DefaultTransport, "test")
		assert.NotNil(t, tr)
	})
}
func TestHTTPTransport_RoundTrip(t *testing.T) {
	t.Run("should record metrics and return response", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Hello, client"))
		}))
		defer ts.Close()

		tr := otelhttpclient.NewHTTPTransport(http.DefaultTransport, "test")

		req, err := http.NewRequest("GET", ts.URL, nil)
		assert.NoError(t, err)

		resp, err := tr.RoundTrip(req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, "Hello, client", string(body))
		resp.Body.Close()
	})

	t.Run("should handle error from RoundTrip", func(t *testing.T) {
		// Create a new HTTP transport with a nil RoundTripper to force an error
		tr := otelhttpclient.NewHTTPTransport(nil, "test")

		// Create a new request
		req, err := http.NewRequest("GET", "http://invalid.url", nil)
		assert.NoError(t, err)

		// Perform the request
		resp, err := tr.RoundTrip(req)
		assert.Error(t, err)
		assert.Nil(t, resp)
	})
}
