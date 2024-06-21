package http

import (
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRetryableTransport_RoundTrip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/success" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusGatewayTimeout)
		}
	}))
	defer server.Close()

	transport := &RetryableTransport{
		Transport:  http.DefaultTransport,
		RetryCount: 3,
	}

	// Test case 1: Successful request
	req, err := http.NewRequest(http.MethodGet, server.URL+"/success", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Unexpected status code: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Test case 2: Retry exhausted
	req, err = http.NewRequest(http.MethodGet, server.URL+"/failure", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	resp, err = transport.RoundTrip(req)
	if err != nil {
		t.Error("Expected nil but got an error")
	}
	if resp == nil {
		t.Error("Expected an error response but got nil")
	}
}

func TestShouldRetry(t *testing.T) {
	// Test case 1: Retry on connection reset error
	err := fmt.Errorf("connection reset by peer")
	resp := &http.Response{StatusCode: http.StatusInternalServerError}
	if !shouldRetry(err, resp) {
		t.Error("shouldRetry returned false, expected true for connection reset error")
	}

	// Test case 2: Retry on status code 504
	resp = &http.Response{StatusCode: http.StatusGatewayTimeout}
	if !shouldRetry(nil, resp) {
		t.Error("shouldRetry returned false, expected true for status code 504")
	}

	// Test case 3: Do not retry on status code 200
	resp = &http.Response{StatusCode: http.StatusOK}
	if shouldRetry(nil, resp) {
		t.Error("shouldRetry returned true, expected false for status code 200")
	}
}

func TestBackoff(t *testing.T) {
	for i := 0; i < 5; i++ {
		backoffDuration := backoff(i)
		expectedDuration := time.Duration(math.Pow(2, float64(i))) * time.Second
		if backoffDuration != expectedDuration {
			t.Errorf("backoff(%d) returned %v, expected %v", i, backoffDuration, expectedDuration)
		}
	}
}
