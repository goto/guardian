package alicatalogapis

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Client interface {
	RoleBindingProjectCreate(ctx context.Context, in *RoleBindingProjectCreateRequest) (*RoleBinding, error)
	RoleBindingProjectGetAll(ctx context.Context, in *RoleBindingProjectGetAllRequest) (*RoleBinding, error)
	
	RoleBindingSchemaCreate(ctx context.Context, in *RoleBindingSchemaCreateRequest) (*RoleBinding, error)
	RoleBindingSchemaGetAll(ctx context.Context, in *RoleBindingSchemaGetAllRequest) (*RoleBinding, error)
	RoleBindingSchemaDelete(ctx context.Context, in *RoleBindingSchemaDeleteRequest) error
}

type client struct {
	accessKeyID     string
	accessKeySecret string
	securityToken   string
	accountID       string
	host            string

	httpClient *http.Client
}

func NewClient(accessKeyID, accessKeySecret, regionID, accountID string, clientOptions ...ClientOption) (Client, error) {
	if accessKeyID == "" {
		return nil, ErrInitMissingAccessKeyID
	}
	if accessKeySecret == "" {
		return nil, ErrInitMissingAccessKeySecret
	}
	if accountID == "" {
		return nil, ErrInitMissingAccountID
	}
	if regionID == "" {
		return nil, ErrInitMissingRegionID
	}
	c := &client{
		accessKeyID:     accessKeyID,
		accessKeySecret: accessKeySecret,
		accountID:       accountID,
		host:            fmt.Sprintf("http://catalogapi.%s.maxcompute.aliyun.com", regionID),
		httpClient:      http.DefaultClient,
	}
	for _, option := range clientOptions {
		option.ApplyTo(c)
	}
	return c, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Client Option
// ---------------------------------------------------------------------------------------------------------------------

type ClientOption interface {
	ApplyTo(c *client)
}

func WithSecurityToken(securityToken string) ClientOption {
	return &withSecurityToken{securityToken}
}

type withSecurityToken struct{ securityToken string }

func (w *withSecurityToken) ApplyTo(c *client) { c.securityToken = w.securityToken }

// ---------------------------------------------------------------------------------------------------------------------
// Client HTTP
// ---------------------------------------------------------------------------------------------------------------------

func (c *client) sendRequestAndUnmarshal(ctx context.Context, method, path string, queryParams url.Values, header map[string]string, rawBody []byte, expectedStatusCode int, unmarshalTarget interface{}) error {
	// sending the actual request
	resp, err := c.sendRawRequest(ctx, method, path, queryParams, header, rawBody)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respErr := newRespErr(resp)
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return respErr.FromErr("fail to read response body", err)
	}
	if resp.StatusCode != expectedStatusCode {
		reason := fmt.Sprintf("unexpected response status code: %v (%v). expected: %v (%v)", resp.StatusCode, http.StatusText(resp.StatusCode), expectedStatusCode, http.StatusText(expectedStatusCode))
		return respErr.FromResponseBody(reason, respBody)
	}
	if err = json.Unmarshal(respBody, unmarshalTarget); err != nil {
		return respErr.FromResponseBody(fmt.Sprintf("fail to unmarshal response body: %v", err.Error()), respBody)
	}
	return nil
}

func (c *client) sendRequest(ctx context.Context, method, path string, queryParams url.Values, header map[string]string, rawBody []byte, expectedStatusCode int) error {
	resp, err := c.sendRawRequest(ctx, method, path, queryParams, header, rawBody)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respErr := newRespErr(resp)
	if resp.StatusCode != expectedStatusCode {
		reason := fmt.Sprintf("unexpected response status code: %v (%v). expected: %v (%v)", resp.StatusCode, http.StatusText(resp.StatusCode), expectedStatusCode, http.StatusText(expectedStatusCode))
		respBody, _ := io.ReadAll(resp.Body)
		return respErr.FromResponseBody(reason, respBody)
	}
	return nil
}

func (c *client) sendRawRequest(ctx context.Context, method, path string, queryParams url.Values, header map[string]string, rawBody []byte) (*http.Response, error) {
	reqURL := fmt.Sprintf("%s/%s", c.host, path)
	if len(queryParams) > 0 {
		reqURL += "?" + queryParams.Encode()
	}
	var reqBody io.Reader
	if len(rawBody) > 0 {
		reqBody = bytes.NewReader(rawBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, reqURL, reqBody)
	if err != nil {
		return nil, fmt.Errorf("fail to create request. %w", err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	c.prepareRequest(req, rawBody)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return resp, fmt.Errorf("fail to send request. %w", err)
	}
	return resp, nil
}

func (c *client) prepareRequest(req *http.Request, rawBody []byte) {
	// canonical queries
	queryParams := req.URL.Query()
	var reqQueries []string
	for key, values := range queryParams {
		var tmp []string
		for _, value := range values {
			if value == "" {
				continue
			}
			tmp = append(tmp, value)
		}
		sort.Strings(tmp)
		for _, v := range tmp {
			reqQueries = append(reqQueries, fmt.Sprintf("%s=%s", key, v))
		}
	}
	sort.Strings(reqQueries)
	canonicalQueries := strings.Join(reqQueries, "&")

	// canonical resource
	canonicalResource := req.URL.Path
	if len(reqQueries) > 0 {
		req.URL.RawQuery = canonicalQueries
		canonicalResource += fmt.Sprintf("?%v", canonicalQueries)
	}

	// canonical headers
	headersToSign := make(map[string]string)
	for key, values := range req.Header {
		lowerKey := strings.ToLower(key)
		if lowerKey == "content-type" || lowerKey == "content-md5" || strings.HasPrefix(lowerKey, "x-odps-") {
			headersToSign[lowerKey] = values[0]
		}
	}
	var (
		contentLength = "0"
		contentType   = ""
		contentMD5    = ""
		securityToken = c.securityToken
		date          = time.Now().UTC().Format(http.TimeFormat)
	)
	if len(rawBody) > 0 {
		contentLength = strconv.Itoa(len(rawBody))
		contentType = "application/json"
		hasher := md5.New()
		hasher.Write(rawBody)
		contentMD5 = hex.EncodeToString(hasher.Sum(nil))
	}

	// override values if present from higher level
	if v := req.Header.Get("Content-Length"); v != "" {
		contentLength = v
	}
	if v := req.Header.Get("Content-Type"); v != "" {
		contentType = v
	}
	if v := req.Header.Get("Content-MD5"); v != "" {
		contentMD5 = v
	}
	if v := req.Header.Get("Authorization-Sts-Token"); v != "" {
		securityToken = v
	}
	if v := req.Header.Get("Date"); v != "" {
		date = v
	}

	headersToSign["content-type"] = contentType
	headersToSign["content-md5"] = contentMD5
	headersToSign["date"] = date

	var headerKeys []string
	for key := range headersToSign {
		headerKeys = append(headerKeys, key)
	}
	sort.Strings(headerKeys)

	canonicalHeaders := []string{req.Method}
	for _, key := range headerKeys {
		v := headersToSign[key]
		if strings.HasPrefix(key, "x-odps-") {
			v = fmt.Sprintf("%s:%s", key, headersToSign[key])
		}
		canonicalHeaders = append(canonicalHeaders, v)
	}

	// generate request auth
	canonicalStr := strings.Join(append(canonicalHeaders, canonicalResource), "\n")
	mac := hmac.New(sha1.New, []byte(c.accessKeySecret))
	mac.Write([]byte(canonicalStr))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	authToken := fmt.Sprintf("ODPS %s:%s", c.accessKeyID, signature)

	// set request headers
	if len(rawBody) > 0 {
		req.Header.Set("Content-Length", contentLength)
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Content-MD5", contentMD5)
	}
	if securityToken != "" {
		req.Header.Set("Authorization-Sts-Token", securityToken)
	}
	req.Header.Set("Date", date)
	req.Header.Set("Authorization", authToken)
}

// ---------------------------------------------------------------------------------------------------------------------
// Client Logger
// ---------------------------------------------------------------------------------------------------------------------

type Logger interface {
	Printf(format string, v ...any)
	Println(v ...any)
}
