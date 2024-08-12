package http

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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
			Type:     "api_key",
			Username: "test",
			Password: "test",
			In:       "query",
			Key:      "test_key",
			Value:    "test_value",
		},
		Method: "GET",
	}, nil)
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
			Type:     "bearer",
			Username: "test",
			Password: "test",
			Token:    "test_token",
		},
		Method: "POST",
		Body:   "test",
	}, nil)
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
			Type:     "bearer",
			Username: "test",
			Password: "test",
			Token:    "test_token",
		},
		Method: "POST",
	}, nil)
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

func TestMakeRequestForPostWithPayloadForHeaderAuth(t *testing.T) {
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
			Type:     "api_key",
			Username: "test",
			Password: "test",
			In:       "header",
			Key:      "test_key",
			Value:    "test_value",
		},
		Method: "POST",
		Body:   "test",
	}, nil)
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

func TestMakeRequestForPostWithPayloadForBasicAuth(t *testing.T) {
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
	}, nil)
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

type MockHttpClientCreator struct {
	mock.Mock
}

func (m *MockHttpClientCreator) GetHttpClientForGoogleOAuth2(ctx context.Context, creds []byte) (*http.Client, error) {
	args := m.Called(ctx, creds)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*http.Client), args.Error(1)
}

func (m *MockHttpClientCreator) GetHttpClientForGoogleIdToken(ctx context.Context, creds []byte, audience string) (*http.Client, error) {
	args := m.Called(ctx, creds, audience)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*http.Client), args.Error(1)
}

func TestNewHTTPClient_GoogleOAuth2(t *testing.T) {
	credsJSON := `{"type":"service_account"}`
	encodedCreds := base64.StdEncoding.EncodeToString([]byte(credsJSON))
	expectedClient := &http.Client{}

	mockCreator := new(MockHttpClientCreator)
	mockCreator.On("GetHttpClientForGoogleOAuth2", mock.Anything, []byte(credsJSON)).Return(expectedClient, nil)

	config := &HTTPClientConfig{
		URL: "https://example.com",
		Auth: &HTTPAuthConfig{
			Type:                  "google_oauth2",
			CredentialsJSONBase64: encodedCreds,
		},
	}

	client, err := NewHTTPClient(config, mockCreator)

	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, expectedClient, client.httpClient)
	mockCreator.AssertExpectations(t)
}

func TestNewHTTPClient_GoogleOAuth2WithEmptyCredentialJson(t *testing.T) {
	mockCreator := new(MockHttpClientCreator)
	config := &HTTPClientConfig{
		URL: "https://example.com",
		Auth: &HTTPAuthConfig{
			Type:                  "google_oauth2",
			CredentialsJSONBase64: "",
		},
	}

	client, err := NewHTTPClient(config, mockCreator)

	assert.Error(t, err, "missing credentials for google_idtoken or  google_oauth2 auth")
	assert.Nil(t, client)
	mockCreator.AssertExpectations(t)
}

func TestNewHTTPClient_GoogleIdToken(t *testing.T) {
	credsJSON := `{"type":"service_account"}`
	encodedCreds := base64.StdEncoding.EncodeToString([]byte(credsJSON))
	expectedClient := &http.Client{}

	mockCreator := new(MockHttpClientCreator)
	mockCreator.On("GetHttpClientForGoogleIdToken", mock.Anything, []byte(credsJSON), "audience").Return(expectedClient, nil)

	config := &HTTPClientConfig{
		URL: "https://example.com",
		Auth: &HTTPAuthConfig{
			Type:                  "google_idtoken",
			CredentialsJSONBase64: encodedCreds,
			Audience:              "audience",
		},
	}

	client, err := NewHTTPClient(config, mockCreator)

	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, expectedClient, client.httpClient)
	mockCreator.AssertExpectations(t)
}

func TestNewHTTPClient_GoogleIdTokenErrorScenario(t *testing.T) {
	credsJSON := `{"type":"service_account"}`
	encodedCreds := base64.StdEncoding.EncodeToString([]byte(credsJSON))

	mockCreator := new(MockHttpClientCreator)
	mockCreator.On("GetHttpClientForGoogleIdToken", mock.Anything, []byte(credsJSON), "audience").Return(nil, fmt.Errorf("error creating http client for google_idtoken"))

	config := &HTTPClientConfig{
		URL: "https://example.com",
		Auth: &HTTPAuthConfig{
			Type:                  "google_idtoken",
			CredentialsJSONBase64: encodedCreds,
			Audience:              "audience",
		},
	}

	_, err := NewHTTPClient(config, mockCreator)

	assert.Equal(t, err.Error(), "error creating http client for google_idtoken")
	mockCreator.AssertExpectations(t)
}

func TestNewHTTPClient_GoogleOAuth2ErrorScenario(t *testing.T) {
	credsJSON := `{"type":"service_account"}`
	encodedCreds := base64.StdEncoding.EncodeToString([]byte(credsJSON))

	mockCreator := new(MockHttpClientCreator)
	mockCreator.On("GetHttpClientForGoogleOAuth2", mock.Anything, []byte(credsJSON)).Return(nil, fmt.Errorf("error creating http client for google_oauth2"))

	config := &HTTPClientConfig{
		URL: "https://example.com",
		Auth: &HTTPAuthConfig{
			Type:                  "google_oauth2",
			CredentialsJSONBase64: encodedCreds,
			Audience:              "audience",
		},
	}

	_, err := NewHTTPClient(config, mockCreator)

	assert.Equal(t, err.Error(), "error creating http client for google_oauth2")
	mockCreator.AssertExpectations(t)
}
