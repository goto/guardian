package optimus

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	pv "github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/utils"
)

const (
	RoleExecuteBackfill = "execute_backfill"
	AccountTypeUser     = "user"
)

type Provider struct {
	pv.UnimplementedClient
	pv.PermissionManager

	typeName string
	logger   log.Logger

	clients map[string]*Client
	mu      sync.Mutex
}

func NewProvider(typeName string, logger log.Logger) *Provider {
	return &Provider{
		typeName: typeName,
		logger:   logger,
		clients:  make(map[string]*Client),
	}
}

func (p *Provider) GetType() string {
	return p.typeName
}

func (p *Provider) CreateConfig(pc *domain.ProviderConfig) error {
	cfg := &config{pc}
	if err := cfg.validate(); err != nil {
		return fmt.Errorf("invalid optimus config: %w", err)
	}
	creds, err := cfg.getCredentials()
	if err != nil {
		return err
	}
	pc.Credentials = creds
	return nil
}

func (p *Provider) GetResources(ctx context.Context, pc *domain.ProviderConfig) ([]*domain.Resource, error) {
	client, err := p.getClient(pc)
	if err != nil {
		return nil, err
	}

	creds, err := (&config{pc}).getCredentials()
	if err != nil {
		return nil, err
	}

	jobResponses, err := client.GetJobs(ctx, creds.ProjectName)
	if err != nil {
		return nil, fmt.Errorf("fetching optimus jobs: %w", err)
	}

	resources := make([]*domain.Resource, 0, len(jobResponses))
	for _, jr := range jobResponses {
		destinationTable := ""
		for _, cfg := range jr.Job.Config {
			if cfg.Name == "DESTINATION_TABLE_ID" {
				destinationTable = cfg.Value
				break
			}
		}

		resources = append(resources, &domain.Resource{
			ProviderType: pc.Type,
			ProviderURN:  pc.URN,
			Type:         ResourceTypeJob,
			URN:          fmt.Sprintf("%s/%s/%s", jr.ProjectName, jr.NamespaceName, jr.Job.Name),
			Name:         jr.Job.Name,
			GlobalURN:    utils.GetGlobalURN(pc.Type, pc.URN, ResourceTypeJob, jr.Job.Name),
			Details: map[string]interface{}{
				"name":                   jr.Job.Name,
				"namespace_name":         jr.NamespaceName,
				"project_name":           jr.ProjectName,
				"schedule":               jr.Job.Interval,
				"owner":                  jr.Job.Owner,
				"status":                 jr.Job.SchedulerState,
				"destination_table_name": destinationTable,
				"task_name":              jr.Job.TaskName,
				"start_date":             jr.Job.StartDate,
			},
		})
	}

	return resources, nil
}

func (p *Provider) GrantAccess(ctx context.Context, _ *domain.ProviderConfig, g domain.Grant) error {
	p.logger.Info(ctx, "optimus grant created in db", "grant_id", g.ID, "account_id", g.AccountID)
	return nil
}

func (p *Provider) RevokeAccess(_ context.Context, _ *domain.ProviderConfig, _ domain.Grant) error {
	return nil
}

func (p *Provider) GetRoles(pc *domain.ProviderConfig, resourceType string) ([]*domain.Role, error) {
	return pv.GetRoles(pc, resourceType)
}

func (p *Provider) GetAccountTypes() []string {
	return []string{AccountTypeUser}
}

func (p *Provider) ValidateAppeal(_ context.Context, a *domain.Appeal) error {
	params, err := getStringParams(a)
	if err != nil {
		return err
	}

	startTimeStr, ok := params["start_time"]
	if !ok || startTimeStr == "" {
		return fmt.Errorf("start_time is required in provider parameters")
	}
	endTimeStr, ok := params["end_time"]
	if !ok || endTimeStr == "" {
		return fmt.Errorf("end_time is required in provider parameters")
	}

	startTime, err := time.Parse(time.RFC3339, startTimeStr)
	if err != nil {
		return fmt.Errorf("invalid start_time %q: must be RFC3339 format (e.g. 2006-01-02T00:00:00Z): %w", startTimeStr, err)
	}
	endTime, err := time.Parse(time.RFC3339, endTimeStr)
	if err != nil {
		return fmt.Errorf("invalid end_time %q: must be RFC3339 format (e.g. 2006-01-02T00:00:00Z): %w", endTimeStr, err)
	}

	if !startTime.Before(endTime) {
		return fmt.Errorf("start_time %q must be before end_time %q", startTimeStr, endTimeStr)
	}

	if a.Resource != nil && a.Resource.Details != nil {
		if jobStartDateStr, ok := a.Resource.Details["start_date"].(string); ok && jobStartDateStr != "" {
			jobStartDate, err := time.Parse("2006-01-02", strings.TrimSpace(jobStartDateStr))
			if err == nil && startTime.UTC().Truncate(24*time.Hour).Before(jobStartDate.UTC()) {
				return fmt.Errorf("replay start_time %q cannot be before the job start_date %q", startTimeStr, jobStartDateStr)
			}
		}
	}

	return nil
}

func getStringParams(a *domain.Appeal) (map[string]string, error) {
	raw, ok := a.Details[domain.ReservedDetailsKeyProviderParameters]
	if !ok {
		return nil, fmt.Errorf("missing %q in appeal details", domain.ReservedDetailsKeyProviderParameters)
	}
	rawMap, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%q must be an object", domain.ReservedDetailsKeyProviderParameters)
	}
	result := make(map[string]string, len(rawMap))
	for k, v := range rawMap {
		if v != nil {
			result[k] = fmt.Sprintf("%v", v)
		}
	}
	return result, nil
}

func (p *Provider) ListAccess(_ context.Context, _ domain.ProviderConfig, _ []*domain.Resource) (domain.MapResourceAccess, error) {
	return domain.MapResourceAccess{}, nil
}

func (p *Provider) IsDuplicateAppeal(ctx context.Context, incoming *domain.Appeal, fetchPending func(context.Context, *domain.ListAppealsFilter) ([]*domain.Appeal, error)) (bool, error) {
	incomingParams, err := getStringParams(incoming)
	if err != nil {
		return false, fmt.Errorf("reading incoming appeal parameters: %w", err)
	}

	incomingStart, err := time.Parse(time.RFC3339, incomingParams["start_time"])
	if err != nil {
		return false, fmt.Errorf("parsing incoming start_time: %w", err)
	}
	incomingEnd, err := time.Parse(time.RFC3339, incomingParams["end_time"])
	if err != nil {
		return false, fmt.Errorf("parsing incoming end_time: %w", err)
	}

	existingPending, err := fetchPending(ctx, &domain.ListAppealsFilter{
		ResourceIDs: []string{incoming.ResourceID},
		Roles:       []string{incoming.Role},
		Statuses:    []string{domain.AppealStatusPending},
	})
	if err != nil {
		return false, fmt.Errorf("fetching pending appeals: %w", err)
	}

	for _, existing := range existingPending {
		if existing.ID == incoming.ID {
			continue
		}
		existingParams, err := getStringParams(existing)
		if err != nil {
			return false, fmt.Errorf("reading existing appeal parameters for appeal %s: %w", existing.ID, err)
		}
		existingStart, err := time.Parse(time.RFC3339, existingParams["start_time"])
		if err != nil {
			return false, fmt.Errorf("parsing existing start_time for appeal %s: %w", existing.ID, err)
		}
		existingEnd, err := time.Parse(time.RFC3339, existingParams["end_time"])
		if err != nil {
			return false, fmt.Errorf("parsing existing end_time for appeal %s: %w", existing.ID, err)
		}
		if !(incomingEnd.Before(existingStart) || existingEnd.Before(incomingStart)) {
			return true, nil
		}
	}
	return false, nil
}

func (p *Provider) getClient(pc *domain.ProviderConfig) (*Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if c, ok := p.clients[pc.URN]; ok {
		return c, nil
	}

	creds, err := (&config{pc}).getCredentials()
	if err != nil {
		return nil, err
	}

	client := NewClient(creds.Host)
	p.clients[pc.URN] = client
	return client, nil
}