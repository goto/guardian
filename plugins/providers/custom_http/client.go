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
	GetResources(ctx context.Context, resourceType string) ([]*Resource, error)
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

func (c *Client) GetResources(ctx context.Context, resourceType string) ([]*Resource, error) {
	// Get configuration for this specific resource type
	resourceConfig, exists := c.config.ResourceTypes[resourceType]
	if !exists {
		return nil, fmt.Errorf("no configuration found for resource type: %s", resourceType)
	}

	url := c.credentials.BaseURL + resourceConfig.API.Resources.Path
	req, err := http.NewRequestWithContext(ctx, resourceConfig.API.Resources.Method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Add headers
	for key, value := range c.credentials.GetHeaders() {
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
		return c.processResourceList(ctx, rawResources, resourceType)
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

	return c.processResourceList(ctx, rawResources, resourceType)
}

func (c *Client) processResourceList(ctx context.Context, rawResources []map[string]interface{}, resourceType string) ([]*Resource, error) {
	resources := make([]*Resource, 0, len(rawResources))
	for _, raw := range rawResources {
		resource, err := c.mapToResource(raw, resourceType)
		if err != nil {
			c.logger.Warn(ctx, "failed to map resource", "error", err, "resource", raw)
			continue
		}

		resources = append(resources, resource)
	}

	return resources, nil
}

func (c *Client) GrantAccess(ctx context.Context, resource *Resource, accountID, role string) error {
	// Get configuration for this resource type
	resourceConfig, exists := c.config.ResourceTypes[resource.Type]
	if !exists {
		return fmt.Errorf("no configuration found for resource type: %s", resource.Type)
	}

	return c.makeAccessRequest(ctx, resourceConfig.API.Grant, resource, accountID, role, "grant")
}

func (c *Client) RevokeAccess(ctx context.Context, resource *Resource, accountID, role string) error {
	// Get configuration for this resource type
	resourceConfig, exists := c.config.ResourceTypes[resource.Type]
	if !exists {
		return fmt.Errorf("no configuration found for resource type: %s", resource.Type)
	}

	return c.makeAccessRequest(ctx, resourceConfig.API.Revoke, resource, accountID, role, "revoke")
}

func (c *Client) makeAccessRequest(ctx context.Context, endpoint APIEndpoint, resource *Resource, accountID, role, action string) error {
	// Build template data with base context for processing custom variables
	templateData := map[string]interface{}{
		"resource":   resource,
		"account_id": accountID,
		"role":       role,
		"action":     action,
	}

	// Add custom template variables (this is where all the magic happens)
	if err := c.addCustomTemplateVariables(templateData, resource, accountID, role, action); err != nil {
		return fmt.Errorf("adding custom template variables: %w", err)
	} // Build URL with template support
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
	for key, value := range c.credentials.GetHeaders() {
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

func (c *Client) mapToResource(rawResource map[string]interface{}, resourceType string) (*Resource, error) {
	// Get configuration for this resource type
	resourceConfig, exists := c.config.ResourceTypes[resourceType]
	if !exists {
		return nil, fmt.Errorf("no configuration found for resource type: %s", resourceType)
	}

	resource := &Resource{}

	// Extract name using mapping
	if nameValue, err := c.extractFieldValue(rawResource, resourceConfig.ResourceMapping.NameField); err == nil {
		resource.Name = fmt.Sprintf("%v", nameValue)
	} else {
		return nil, fmt.Errorf("extracting name field: %w", err)
	}

	// Extract ID using mapping
	if idValue, err := c.extractFieldValue(rawResource, resourceConfig.ResourceMapping.IDField); err == nil {
		resource.ID = fmt.Sprintf("%v", idValue)
	} else {
		return nil, fmt.Errorf("extracting id field: %w", err)
	}

	// Generate URN from ID if no specific URN field configured
	resource.URN = resource.ID

	// Set resource type from the resource type parameter
	resource.Type = resourceType

	// Store original data as details
	resource.Details = rawResource

	return resource, nil
}

func (c *Client) addCustomTemplateVariables(templateData map[string]interface{}, resource *Resource, accountID, role, action string) error {
	// Get configuration for this resource type
	resourceConfig, exists := c.config.ResourceTypes[resource.Type]
	if !exists {
		return fmt.Errorf("no configuration found for resource type: %s", resource.Type)
	}

	// Add custom template variables if configured
	for varName, varTemplate := range resourceConfig.TemplateVariables {
		// Create template data for processing the variable template
		varTemplateData := map[string]interface{}{
			"resource":   resource,
			"account_id": accountID,
			"role":       role,
			"action":     action,
		}

		// Process the variable template
		varValue, err := c.renderTemplate(varTemplate, varTemplateData)
		if err != nil {
			return fmt.Errorf("processing template variable %s: %w", varName, err)
		}

		// Add the processed variable to template data
		templateData[varName] = varValue
	}

	return nil
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
