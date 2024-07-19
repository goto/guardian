package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

type Client struct {
	baseURL *url.URL
	options *options
}

func NewClient(baseURL string, opts ...ClientOption) (*Client, error) {
	url, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	client := &Client{
		baseURL: url,
		options: &options{
			httpClient: http.DefaultClient,
		},
	}
	for _, o := range opts {
		o(client.options)
	}
	return client, nil
}

type ListGroupsRequest struct {
	Page    int
	PerPage int
}

func (c *Client) ListGroups(ctx context.Context, req *ListGroupsRequest) ([]*Group, *http.Response, error) {
	path := "/api/v1/groups"
	r, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, err
	}

	q := r.URL.Query()
	if req.Page != 0 {
		q.Add("page", strconv.Itoa(req.Page))
	}
	if req.PerPage != 0 {
		q.Add("per_page", strconv.Itoa(req.PerPage))
	}
	r.URL.RawQuery = q.Encode()

	res, err := c.options.httpClient.Do(r)
	if err != nil {
		return nil, res, err
	}

	var resBody []*Group
	if err := parseResponseBody(res.Body, &resBody); err != nil {
		return nil, res, err
	}

	return resBody, res, nil
}

func (c *Client) AddUserToGroup(ctx context.Context, groupID, userID int) (*http.Response, error) {
	path := fmt.Sprintf("/api/v1/groups/%d/users", groupID)
	reqBody := map[string]any{"user_id": userID}
	r, err := c.newRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	res, err := c.options.httpClient.Do(r)
	if err != nil {
		return res, err
	}

	return res, nil
}

func (c *Client) RemoveUserFromGroup(ctx context.Context, groupID, userID int) (*http.Response, error) {
	path := fmt.Sprintf("/api/v1/groups/%d/users/%d", groupID, userID)
	r, err := c.newRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	res, err := c.options.httpClient.Do(r)
	if err != nil {
		return res, err
	}

	return res, nil
}

func (c *Client) newRequest(ctx context.Context, method, path string, body interface{}) (*http.Request, error) {
	url, err := c.baseURL.Parse(path)
	if err != nil {
		return nil, err
	}

	var reqBody io.ReadWriter
	if body != nil {
		reqBody = new(bytes.Buffer)
		if err := json.NewEncoder(reqBody).Encode(body); err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url.String(), reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	if c.options.token != "" {
		req.Header.Add("Authorization", c.options.token)
	}

	return req, nil
}

func parseResponseBody(resBody io.ReadCloser, v interface{}) error {
	defer resBody.Close()
	return json.NewDecoder(resBody).Decode(v)
}
