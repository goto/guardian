package gate

import (
	"net/http"
)

type options struct {
	httpClient        *http.Client
	token             string
	queryParamAuthKey string
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

func WithQueryParamAuthMethod() ClientOption {
	return func(opts *options) {
		opts.queryParamAuthKey = "token"
	}
}
