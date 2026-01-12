package custom_http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/goto/guardian/pkg/log"
)

type HTTPClient interface {
	GetResources(ctx context.Context) ([]*Resource, error)
	GrantAccess(ctx context.Context, resource *Resource, accountID, role string) error
	RevokeAccess(ctx context.Context, resource *Resource, accountID, role string) error
}

type Client struct {
	credentials Credentials
	config      ProviderConfiguration
	httpClient  *http.Client
	logger      log.Logger
}

func NewClient(creds Credentials, config ProviderConfiguration, logger log.Logger) *Client {
	return &Client{
		credentials: creds,
		config:      config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

func (c *Client) GetResources(ctx context.Context) ([]*Resource, error) {
	url := c.credentials.BaseURL + c.config.API.Resources.Path
	req, err := http.NewRequestWithContext(ctx, c.config.API.Resources.Method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Add headers
	for key, value := range c.credentials.Headers {
		req.Header.Set(key, value)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	// Handle both direct array and wrapped response formats
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		// Try parsing as direct array
		var rawResources []map[string]interface{}
		if err := json.Unmarshal(body, &rawResources); err != nil {
			return nil, fmt.Errorf("unmarshaling response: %w", err)
		}
		return c.processResourceList(ctx, rawResources)
	}

	// Extract data array from wrapped response
	var rawResources []map[string]interface{}
	if dataField, exists := response["data"]; exists {
		if dataArray, ok := dataField.([]interface{}); ok {
			for _, item := range dataArray {
				if itemMap, ok := item.(map[string]interface{}); ok {
					rawResources = append(rawResources, itemMap)
				}
			}
		}
	} else {
		// Fallback: treat entire response as single resource
		rawResources = []map[string]interface{}{response}
	}

	return c.processResourceList(ctx, rawResources)
}

func (c *Client) processResourceList(ctx context.Context, rawResources []map[string]interface{}) ([]*Resource, error) {
	resources := make([]*Resource, 0, len(rawResources))
	for _, raw := range rawResources {
		resource, err := c.mapToResource(raw)
		if err != nil {
			c.logger.Warn(ctx, "failed to map resource", "error", err, "resource", raw)
			continue
		}

		// Fetch approvers for this resource if it has members endpoint
		if err := c.enrichResourceWithApprovers(ctx, resource, raw); err != nil {
			c.logger.Warn(ctx, "failed to fetch approvers", "error", err, "resource_id", resource.ID)
		}

		resources = append(resources, resource)
	}

	return resources, nil
}

func (c *Client) GrantAccess(ctx context.Context, resource *Resource, accountID, role string) error {
	return c.makeAccessRequest(ctx, c.config.API.Grant, resource, accountID, role, "grant")
}

func (c *Client) RevokeAccess(ctx context.Context, resource *Resource, accountID, role string) error {
	// For revoke operations, we need to find the group member ID first
	groupMemberID, err := c.findGroupMemberID(ctx, resource.ID, accountID)
	if err != nil {
		return fmt.Errorf("finding group member ID: %w", err)
	}

	// Prepare template data with group member ID
	templateData := map[string]interface{}{
		"account_id":      accountID,
		"resource_id":     resource.ID,
		"resource":        resource,
		"role":            role,
		"action":          "revoke",
		"group_member_id": groupMemberID,
	}

	return c.makeAccessRequestWithData(ctx, c.config.API.Revoke, templateData)
}

func (c *Client) makeAccessRequest(ctx context.Context, endpoint APIEndpoint, resource *Resource, accountID, role, action string) error {
	// Prepare template data
	templateData := map[string]interface{}{
		"account_id":  accountID,
		"resource_id": resource.ID,
		"resource":    resource,
		"role":        role,
		"action":      action,
	}

	return c.makeAccessRequestWithData(ctx, endpoint, templateData)
}

func (c *Client) makeAccessRequestWithData(ctx context.Context, endpoint APIEndpoint, templateData map[string]interface{}) error {
	// Build URL with template support
	url, err := c.renderTemplate(c.credentials.BaseURL+endpoint.Path, templateData)
	if err != nil {
		return fmt.Errorf("rendering URL template: %w", err)
	}

	// Build request body if configured
	var requestBody io.Reader
	if endpoint.Body != nil {
		body, err := c.buildRequestBody(endpoint.Body, templateData)
		if err != nil {
			return fmt.Errorf("building request body: %w", err)
		}
		requestBody = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, endpoint.Method, url, requestBody)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	for key, value := range c.credentials.Headers {
		req.Header.Set(key, value)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *Client) enrichResourceWithApprovers(ctx context.Context, resource *Resource, rawResource map[string]interface{}) error {
	// Check if we have a members endpoint configured
	if c.config.API.Members.Path == "" {
		return nil // Skip if no members endpoint configured
	}

	// Build members URL
	templateData := map[string]interface{}{
		"resource_id": resource.ID,
		"resource":    resource,
	}

	membersURL, err := c.renderTemplate(c.credentials.BaseURL+c.config.API.Members.Path, templateData)
	if err != nil {
		return fmt.Errorf("rendering members URL template: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, c.config.API.Members.Method, membersURL, nil)
	if err != nil {
		return fmt.Errorf("creating members request: %w", err)
	}

	// Add headers
	for key, value := range c.credentials.Headers {
		req.Header.Set(key, value)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("making members request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil // Skip if members endpoint fails
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading members response body: %w", err)
	}

	var membersResponse map[string]interface{}
	if err := json.Unmarshal(body, &membersResponse); err != nil {
		return nil // Skip if parsing fails
	}

	// Extract approvers (members with is_admin: true)
	var approvers []string
	if dataField, exists := membersResponse["data"]; exists {
		if dataArray, ok := dataField.([]interface{}); ok {
			for _, item := range dataArray {
				if member, ok := item.(map[string]interface{}); ok {
					if isAdmin, exists := member["is_admin"]; exists && isAdmin == true {
						if email, exists := member["email_address"]; exists {
							if emailStr, ok := email.(string); ok {
								approvers = append(approvers, emailStr)
							}
						}
					}
				}
			}
		}
	}

	// Add approvers to resource details
	if resource.Details == nil {
		resource.Details = make(map[string]interface{})
	}
	resource.Details["approvers"] = approvers

	return nil
}

func (c *Client) findGroupMemberID(ctx context.Context, groupID, accountID string) (string, error) {
	// Check if we have a members endpoint configured
	if c.config.API.Members.Path == "" {
		return "", fmt.Errorf("members endpoint not configured")
	}

	// Build members URL
	templateData := map[string]interface{}{
		"resource_id": groupID,
	}

	membersURL, err := c.renderTemplate(c.credentials.BaseURL+c.config.API.Members.Path, templateData)
	if err != nil {
		return "", fmt.Errorf("rendering members URL template: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, c.config.API.Members.Method, membersURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating members request: %w", err)
	}

	// Add headers
	for key, value := range c.credentials.Headers {
		req.Header.Set(key, value)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("making members request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("members API returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading members response body: %w", err)
	}

	var membersResponse map[string]interface{}
	if err := json.Unmarshal(body, &membersResponse); err != nil {
		return "", fmt.Errorf("unmarshaling members response: %w", err)
	}

	// Find the member by email/username
	if dataField, exists := membersResponse["data"]; exists {
		if dataArray, ok := dataField.([]interface{}); ok {
			for _, item := range dataArray {
				if member, ok := item.(map[string]interface{}); ok {
					// Check email_address or username match
					email, hasEmail := member["email_address"]
					username, hasUsername := member["username"]

					if (hasEmail && email == accountID) || (hasUsername && username == accountID) {
						if memberID, exists := member["id"]; exists {
							return fmt.Sprintf("%v", memberID), nil
						}
					}
				}
			}
		}
	}

	return "", fmt.Errorf("group member not found for account %s in group %s", accountID, groupID)
}

func (c *Client) buildRequestBody(bodyTemplate map[string]interface{}, data map[string]interface{}) (string, error) {
	// Process the body template with data
	processedBody, err := c.processTemplate(bodyTemplate, data)
	if err != nil {
		return "", fmt.Errorf("processing body template: %w", err)
	}

	body, err := json.Marshal(processedBody)
	if err != nil {
		return "", fmt.Errorf("marshaling body: %w", err)
	}

	return string(body), nil
}

func (c *Client) processTemplate(template interface{}, data map[string]interface{}) (interface{}, error) {
	switch v := template.(type) {
	case string:
		// Check if string contains template variables
		if strings.Contains(v, "{{.") {
			return c.renderTemplate(v, data)
		}
		return v, nil
	case map[string]interface{}:
		result := make(map[string]interface{})
		for key, value := range v {
			processed, err := c.processTemplate(value, data)
			if err != nil {
				return nil, err
			}
			result[key] = processed
		}
		return result, nil
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, value := range v {
			processed, err := c.processTemplate(value, data)
			if err != nil {
				return nil, err
			}
			result[i] = processed
		}
		return result, nil
	default:
		return v, nil
	}
}

func (c *Client) renderTemplate(templateStr string, data map[string]interface{}) (string, error) {
	tmpl, err := template.New("request").Parse(templateStr)
	if err != nil {
		return "", fmt.Errorf("parsing template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("executing template: %w", err)
	}

	return buf.String(), nil
}

func (c *Client) mapToResource(rawResource map[string]interface{}) (*Resource, error) {
	resource := &Resource{}

	// Extract name using mapping
	if nameValue, err := c.extractFieldValue(rawResource, c.config.Mapping.Name); err == nil {
		resource.Name = fmt.Sprintf("%v", nameValue)
	} else {
		return nil, fmt.Errorf("extracting name field: %w", err)
	}

	// Extract ID using mapping
	if idValue, err := c.extractFieldValue(rawResource, c.config.Mapping.ID); err == nil {
		resource.ID = fmt.Sprintf("%v", idValue)
	} else {
		return nil, fmt.Errorf("extracting id field: %w", err)
	}

	// Extract URN using mapping
	if urnValue, err := c.extractFieldValue(rawResource, c.config.Mapping.URN); err == nil {
		resource.URN = fmt.Sprintf("%v", urnValue)
	} else {
		return nil, fmt.Errorf("extracting urn field: %w", err)
	}

	// Store original data as details
	resource.Details = rawResource

	return resource, nil
}

func (c *Client) extractFieldValue(data map[string]interface{}, fieldPath string) (interface{}, error) {
	// Support nested field paths like "data.attributes.name"
	parts := strings.Split(fieldPath, ".")
	current := data

	for i, part := range parts {
		if i == len(parts)-1 {
			// Last part, return the value
			value, exists := current[part]
			if !exists {
				return nil, fmt.Errorf("field %q not found in path %q", part, fieldPath)
			}
			return value, nil
		}

		// Navigate to nested object
		next, exists := current[part]
		if !exists {
			return nil, fmt.Errorf("field %q not found in path %q", part, fieldPath)
		}

		nextMap, ok := next.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("field %q is not an object in path %q", part, fieldPath)
		}
		current = nextMap
	}

	return nil, fmt.Errorf("empty field path")
}
