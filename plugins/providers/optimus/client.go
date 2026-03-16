package optimus

import (
	"bytes"
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

type replayRequest struct {
	ProjectName   string `json:"projectName"`
	JobName       string `json:"jobName"`
	NamespaceName string `json:"namespaceName"`
	StartTime     string `json:"startTime"`
	EndTime       string `json:"endTime"`
	Parallel      bool   `json:"parallel"`
	Description   string `json:"description"`
	JobConfig     string `json:"jobConfig"`
	Category      string `json:"category"`
	Status        string `json:"status"`
	RequesterID   string `json:"requester_id"`
}

type replayResponse struct {
	ID string `json:"id"`
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

func (c *Client) CreateReplay(ctx context.Context, r *replayRequest) (*replayResponse, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("marshaling replay request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/v1beta1/project/%s/replay", c.host, r.ProjectName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("creating replay request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing replay request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("create replay returned status %d", resp.StatusCode)
	}

	var result replayResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding replay response: %w", err)
	}

	return &result, nil
}
