package http

import (
	"bytes"
	"io"
	"math"
	"net/http"
	"time"
)

type RetryableTransport struct {
	Transport  http.RoundTripper
	RetryCount int
}

func (t *RetryableTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var bodyBytes []byte
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading body: %w", err)
	}

	var resp *http.Response
	retries := -1
	for shouldRetry(err, resp) && retries < t.RetryCount {
		if retries > -1 {
			time.Sleep(backoff(retries))
			// consume any response to reuse the connection.
			drainBody(resp)
		}

		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		resp, err = t.Transport.RoundTrip(req)

		retries++
	}

	return resp, err
}

func backoff(retries int) time.Duration {
	return time.Duration(math.Pow(2, float64(retries))) * time.Second
}

func shouldRetry(err error, resp *http.Response) bool {
	if err != nil {
		return true
	}

	return resp.StatusCode == http.StatusBadGateway ||
		resp.StatusCode == http.StatusServiceUnavailable ||
		resp.StatusCode == http.StatusGatewayTimeout
}

func drainBody(resp *http.Response) {
	if resp.Body != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}
