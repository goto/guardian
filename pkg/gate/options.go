package gate

import (
	"net/http"
)

type options struct {
	httpClient *http.Client
	token      string
}

type ClientOption func(*options)

func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(opts *options) {
		opts.httpClient = httpClient
	}
}

func WithAPIKey(token string) ClientOption {
	return func(opts *options) {
		opts.token = token
	}
}
