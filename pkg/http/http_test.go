package http

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMakeRequestForGet(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message": "success"}`))
	}))
	defer server.Close()

	// Create an instance of HTTPClient
	client, err := NewHTTPClient(&HTTPClientConfig{
		URL: server.URL,
		Auth: &HTTPAuthConfig{
			Type:     "basic",
			Username: "test",
			Password: "test",
		},
		Method: "GET",
	})
	if err != nil {
		t.Fatalf("Failed to create HTTPClient: %v", err)
	}

	// Call the MakeRequest function
	resp, err := client.MakeRequest(context.Background())
	if err != nil {
		t.Fatalf("MakeRequest failed: %v", err)
	}

	// Check the response status code
	if status := resp.StatusCode; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the response body
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	if string(body) != `{"message": "success"}` {
		t.Errorf("handler returned unexpected body: got %v want %v", string(body), `{"message": "success"}`)
	}
}

func TestMakeRequestForPostWithoutPayload(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message": "success"}`))
	}))
	defer server.Close()

	// Create an instance of HTTPClient
	client, err := NewHTTPClient(&HTTPClientConfig{
		URL: server.URL,
		Auth: &HTTPAuthConfig{
			Type:     "basic",
			Username: "test",
			Password: "test",
		},
		Method: "POST",
	})
	if err != nil {
		t.Fatalf("Failed to create HTTPClient: %v", err)
	}

	// Call the MakeRequest function
	resp, err := client.MakeRequest(context.Background())
	if err != nil {
		t.Fatalf("MakeRequest failed: %v", err)
	}

	// Check the response status code
	if status := resp.StatusCode; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the response body
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	if string(body) != `{"message": "success"}` {
		t.Errorf("handler returned unexpected body: got %v want %v", string(body), `{"message": "success"}`)
	}
}

func TestMakeRequestForPostWithPayload(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message": "success"}`))
	}))
	defer server.Close()

	// Create an instance of HTTPClient
	client, err := NewHTTPClient(&HTTPClientConfig{
		URL: server.URL,
		Auth: &HTTPAuthConfig{
			Type:     "basic",
			Username: "test",
			Password: "test",
		},
		Method: "POST",
		Body:   "test",
	})
	if err != nil {
		t.Fatalf("Failed to create HTTPClient: %v", err)
	}

	// Call the MakeRequest function
	resp, err := client.MakeRequest(context.Background())
	if err != nil {
		t.Fatalf("MakeRequest failed: %v", err)
	}

	// Check the response status code
	if status := resp.StatusCode; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the response body
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	if string(body) != `{"message": "success"}` {
		t.Errorf("handler returned unexpected body: got %v want %v", string(body), `{"message": "success"}`)
	}
}
