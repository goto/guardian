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
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/moul/http2curl"
)

type Client interface {
	RoleCreate(ctx context.Context, in *RoleCreateRequest) (*Role, error)
	RoleGet(ctx context.Context, in *RoleGetRequest) (*Role, error)
	RoleGetAll(ctx context.Context, in *RoleGetAllRequest) ([]*Role, error)
	RoleUpdate(ctx context.Context, in *RoleUpdateRequest) (*Role, error)
	RoleDelete(ctx context.Context, in *RoleDeleteRequest) error

	RoleBindingNamespaceCreate(ctx context.Context, in *RoleBindingNamespaceCreateRequest) (*RoleBinding, error)
	RoleBindingNamespaceGet(ctx context.Context, in *RoleBindingNamespaceGetRequest) (*RoleBinding, error)
	RoleBindingNamespaceDelete(ctx context.Context, in *RoleBindingNamespaceDeleteRequest) error

	RoleBindingSchemaCreate(ctx context.Context, in *RoleBindingSchemaCreateRequest) (*RoleBinding, error)
	RoleBindingSchemaGet(ctx context.Context, in *RoleBindingSchemaGetRequest) (*RoleBinding, error)
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

	debugMode   bool
	debugLogger Logger
}

func NewClient(accessKeyID, accessKeySecret, regionID, accountID string, clientOptions ...ClientOption) (Client, error) {
	if accessKeyID == "" {
		return nil, fmt.Errorf("access key id is missing")
	}
	if accessKeySecret == "" {
		return nil, fmt.Errorf("access key secret is missing")
	}
	if accountID == "" {
		return nil, fmt.Errorf("account id is missing")
	}
	if regionID == "" {
		return nil, fmt.Errorf("region id is missing")
	}
	c := &client{
		accessKeyID:     accessKeyID,
		accessKeySecret: accessKeySecret,
		accountID:       accountID,
		host:            fmt.Sprintf("http://catalogapi.%s.maxcompute.aliyun.com", regionID),
	}
	for _, option := range clientOptions {
		option.ApplyTo(c)
	}
	if c.httpClient == nil {
		c.httpClient = http.DefaultClient
	}
	if c.debugMode && c.debugLogger == nil {
		c.debugLogger = log.New(os.Stdout, "", 0)
	}
	return c, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Client Option
// ---------------------------------------------------------------------------------------------------------------------

type ClientOption interface {
	ApplyTo(c *client)
}

func WithHTTPClient(httpClient *http.Client) ClientOption {
	return &withHTTPClient{httpClient}
}

type withHTTPClient struct{ httpClient *http.Client }

func (w *withHTTPClient) ApplyTo(c *client) { c.httpClient = w.httpClient }

func WithSecurityToken(securityToken string) ClientOption {
	return &withSecurityToken{securityToken}
}

type withSecurityToken struct{ securityToken string }

func (w *withSecurityToken) ApplyTo(c *client) { c.securityToken = w.securityToken }

func WithDebugMode() ClientOption {
	return &withDebugMode{}
}

type withDebugMode struct{}

func (w *withDebugMode) ApplyTo(c *client) { c.debugMode = true }

func WithDebugLogger(logger Logger) ClientOption {
	return &withDebugLogger{logger}
}

type withDebugLogger struct{ logger Logger }

func (w *withDebugLogger) ApplyTo(c *client) { c.debugLogger = w.logger }

// ---------------------------------------------------------------------------------------------------------------------
// Client HTTP
// ---------------------------------------------------------------------------------------------------------------------

func (c *client) sendRequestAndUnmarshal(ctx context.Context, method, path string, queryParams url.Values, header map[string]string, rawBody []byte, expectedStatusCode int, unmarshalTarget interface{}) error {
	resp, err := c.sendRawRequest(ctx, method, path, queryParams, header, rawBody)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respErr := &commonRespErr{RequestID: resp.Header.Get("x-odps-request-id"), StatusCode: resp.StatusCode}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return respErr.FromErr("fail to read response body", err)
	}
	if c.debugMode && len(respBody) > 0 {
		ps(c.debugLogger)
		c.debugLogger.Printf(" - RESP BODY\n%s\n", respBody)
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
	respErr := &commonRespErr{RequestID: resp.Header.Get("x-odps-request-id"), StatusCode: resp.StatusCode}
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
		return nil, err
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	c.prepareRequest(req, rawBody)
	if c.debugMode {
		curl, _ := http2curl.GetCurlCommand(req)
		curlStr := curl.String()
		requestHeaderStr := fmt.Sprint(req.Header)
		for _, sensitiveHeaderKey := range []string{"Authorization", "Authorization-Sts-Token"} {
			if v := req.Header.Get(sensitiveHeaderKey); v != "" {
				curlStr = strings.ReplaceAll(curlStr, v, "{TRUNCATED}")
				requestHeaderStr = strings.ReplaceAll(requestHeaderStr, v, "{TRUNCATED}")
			}
		}
		ps(c.debugLogger)
		c.debugLogger.Printf(" => [%v] %v\n", method, reqURL)
		if len(req.Header) > 0 {
			ps(c.debugLogger)
			c.debugLogger.Printf(" - REQ HEADER\n%s\n", requestHeaderStr)
		}
		if len(rawBody) > 0 {
			ps(c.debugLogger)
			c.debugLogger.Printf(" - REQ BODY\n%s\n", rawBody)
		}
		if curlStr != "" {
			ps(c.debugLogger)
			c.debugLogger.Printf(" - REQ CURL \n%s\n", curlStr)
		}
	}
	return c.httpClient.Do(req)
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
		if strings.HasPrefix(key, "x-odps-") {
			canonicalHeaders = append(canonicalHeaders, key+":"+headersToSign[key])
		} else {
			canonicalHeaders = append(canonicalHeaders, headersToSign[key])
		}
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

func ps(logger Logger) {
	logger.Println(strings.Repeat("-", 50))
}
