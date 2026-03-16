package optimus

import (
	"context"
	"fmt"
	"sync"

	pv "github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/utils"
	"github.com/mitchellh/mapstructure"
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
			},
		})
	}

	return resources, nil
}

func (p *Provider) GrantAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	if g.Appeal == nil {
		return fmt.Errorf("grant has no associated appeal")
	}

	params, err := extractProviderParameters(g.Appeal.Details)
	if err != nil {
		return fmt.Errorf("extracting provider parameters: %w", err)
	}

	creds, err := (&config{pc}).getCredentials()
	if err != nil {
		return err
	}

	parallel := false
	if v, ok := params["parallel"]; ok {
		switch val := v.(type) {
		case bool:
			parallel = val
		case string:
			parallel = val == "true"
		}
	}

	replayReq := &replayRequest{
		ProjectName:   creds.ProjectName,
		JobName:       fmt.Sprintf("%v", params["job_name"]),
		NamespaceName: fmt.Sprintf("%v", params["namespace_name"]),
		StartTime:     fmt.Sprintf("%v", params["start_time"]),
		EndTime:       fmt.Sprintf("%v", params["end_time"]),
		Parallel:      parallel,
		Description:   fmt.Sprintf("%v", params["description"]),
		JobConfig:     fmt.Sprintf("%v", params["job_config"]),
		Category:      fmt.Sprintf("%v", params["category"]),
		Status:        "granted",
		RequesterID:   g.ID,
	}

	client, err := p.getClient(pc)
	if err != nil {
		return err
	}

	result, err := client.CreateReplay(ctx, replayReq)
	if err != nil {
		return fmt.Errorf("creating optimus replay: %w", err)
	}

	p.logger.Info(ctx, "optimus replay created", "replay_id", result.ID, "job_name", replayReq.JobName)
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

func (p *Provider) ListAccess(_ context.Context, _ domain.ProviderConfig, _ []*domain.Resource) (domain.MapResourceAccess, error) {
	return domain.MapResourceAccess{}, nil
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

func extractProviderParameters(details map[string]interface{}) (map[string]interface{}, error) {
	raw, ok := details[domain.ReservedDetailsKeyProviderParameters]
	if !ok {
		return nil, fmt.Errorf("missing %q in appeal details", domain.ReservedDetailsKeyProviderParameters)
	}

	result := make(map[string]interface{})
	if err := mapstructure.Decode(raw, &result); err != nil {
		return nil, fmt.Errorf("decoding provider parameters: %w", err)
	}
	return result, nil
}
