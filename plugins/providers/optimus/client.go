package optimus

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type jobConfig struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type jobWindow struct {
	Preset     string `json:"preset"`
	Size       string `json:"size"`
	Delay      string `json:"delay"`
	ShiftBy    string `json:"shiftBy"`
	Location   string `json:"location"`
	TruncateTo string `json:"truncateTo"`
}

type jobSpec struct {
	Name           string      `json:"name"`
	Owner          string      `json:"owner"`
	StartDate      string      `json:"startDate"`
	EndDate        string      `json:"endDate"`
	Interval       string      `json:"interval"`
	SchedulerState string      `json:"schedulerState"`
	TaskName       string      `json:"taskName"`
	Destination    string      `json:"destination"`
	Window         jobWindow   `json:"window"`
	Config         []jobConfig `json:"config"`
}

type jobSpecificationResponse struct {
	ProjectName   string  `json:"projectName"`
	NamespaceName string  `json:"namespaceName"`
	Job           jobSpec `json:"job"`
}

type listJobsResponse struct {
	JobSpecificationResponses []jobSpecificationResponse `json:"jobSpecificationResponses"`
}

type Client struct {
	host       string
	httpClient *http.Client
}

func NewClient(host string) *Client {
	return &Client{
		host:       host,
		httpClient: &http.Client{},
	}
}

func (c *Client) GetJobs(ctx context.Context, projectName string) ([]jobSpecificationResponse, error) {
	endpoint, err := url.Parse(fmt.Sprintf("%s/api/v1beta1/jobs", c.host))
	if err != nil {
		return nil, fmt.Errorf("parsing jobs URL: %w", err)
	}
	q := endpoint.Query()
	q.Set("project_name", projectName)
	q.Set("ignore_assets", "true")
	endpoint.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating get jobs request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing get jobs request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get jobs returned status %d", resp.StatusCode)
	}

	var result listJobsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding get jobs response: %w", err)
	}

	return result.JobSpecificationResponses, nil
}
