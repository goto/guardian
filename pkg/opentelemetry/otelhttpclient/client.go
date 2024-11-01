package otelhttpclient

import (
	"net/http"
)

func New(name string, client *http.Client) *http.Client {
	if client == nil {
		return &http.Client{
			Transport: NewHTTPTransport(nil, name),
		}
	}
	client.Transport = NewHTTPTransport(client.Transport, name)
	return client
}
