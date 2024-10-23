package otelhttpclient

import (
	"net/http"
)

func New(name string, client *http.Client) *http.Client {
	if client == nil {
		return NewClient(name)
	}
	return NewFromClient(client, name)
}

func NewClient(name string) *http.Client {
	return &http.Client{
		Transport: NewHTTPTransport(nil, name),
	}
}

func NewFromClient(httpClient *http.Client, name string) *http.Client {
	httpClient.Transport = NewHTTPTransport(httpClient.Transport, name)
	return httpClient
}
