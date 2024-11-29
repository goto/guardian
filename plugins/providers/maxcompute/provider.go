package maxcompute

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	openapi "github.com/alibabacloud-go/darabonba-openapi/client"
	openapiv2 "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	maxcompute "github.com/alibabacloud-go/maxcompute-20220104/client"
	sts "github.com/alibabacloud-go/sts-20150401/client"
	"github.com/aliyun/aliyun-odps-go-sdk/odps"
	"github.com/aliyun/aliyun-odps-go-sdk/odps/account"
	pv "github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/utils"
	"golang.org/x/net/context"
)

//go:generate mockery --name=encryptor --exported --with-expecter
type encryptor interface {
	domain.Crypto
}

type provider struct {
	pv.UnimplementedClient
	pv.PermissionManager
	typeName    string
	encryptor   encryptor
	restClients map[string]*maxcompute.Client
	odpsClients map[string]*odps.Odps
	logger      log.Logger
	mu          sync.Mutex
}

func New(
	typeName string,
	encryptor encryptor,
	logger log.Logger,
) *provider {
	return &provider{
		typeName:    typeName,
		encryptor:   encryptor,
		restClients: make(map[string]*maxcompute.Client),
		odpsClients: make(map[string]*odps.Odps),

		logger: logger,
	}
}

func (p *provider) GetType() string {
	return p.typeName
}

func (p *provider) GetAccountTypes() []string {
	return []string{accountTypeRAMUser, accountTypeRAMRole}
}

func (p *provider) GetRoles(pc *domain.ProviderConfig, resourceType string) ([]*domain.Role, error) {
	return pv.GetRoles(pc, resourceType)
}

func (p *provider) CreateConfig(pc *domain.ProviderConfig) error {
	cfg := &config{pc}
	if err := cfg.validate(); err != nil {
		return fmt.Errorf("invalid maxcompute config: %w", err)
	}

	// encrypt sensitive config
	creds, err := cfg.getCredentials()
	if err != nil {
		return err
	}
	if err := creds.encrypt(p.encryptor); err != nil {
		return fmt.Errorf("failed to encrypt credentials: %w", err)
	}
	pc.Credentials = creds

	return nil
}

func (p *provider) GetResources(ctx context.Context, pc *domain.ProviderConfig) ([]*domain.Resource, error) {
	client, err := p.getRestClient(pc)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize maxcompute rest client: %w", err)
	}

	resources := make([]*domain.Resource, 0)
	availableResourceTypes := pc.GetResourceTypes()

	var marker *string
	for {
		res, err := client.ListProjects(&maxcompute.ListProjectsRequest{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list projects: %w", err)
		}

		for _, project := range res.Body.Data.Projects {
			accountID := strings.TrimPrefix(*project.Owner, "ALIYUN$")
			if slices.Contains(availableResourceTypes, resourceTypeProject) {
				resources = append(resources, &domain.Resource{
					ProviderType: pc.Type,
					ProviderURN:  pc.URN,
					Type:         resourceTypeProject,
					URN:          *project.Name,
					Name:         *project.Name,
					GlobalURN:    utils.GetGlobalURN("maxcompute", accountID, resourceTypeProject, *project.Name),
				})
			}

			if slices.Contains(availableResourceTypes, resourceTypeTable) {
				tableRes, err := client.ListTables(project.Name, &maxcompute.ListTablesRequest{})
				if err != nil {
					return nil, fmt.Errorf("failed to list tables for project %s: %w", *project.Name, err)
				}

				for _, table := range tableRes.Body.Data.Tables {
					var urn string
					if table.Schema == nil {
						urn = fmt.Sprintf("%s.%s", *project.Name, *table.Name)
					} else {
						urn = fmt.Sprintf("%s.%s.%s", *project.Name, *table.Schema, *table.Name)
					}
					fmt.Printf("table: %v\n", urn)
					resources = append(resources, &domain.Resource{
						ProviderType: pc.Type,
						ProviderURN:  pc.URN,
						Type:         resourceTypeTable,
						URN:          urn,
						Name:         *table.Name,
						GlobalURN:    utils.GetGlobalURN("maxcompute", accountID, resourceTypeTable, urn),
					})
				}
			}
		}

		if res.Body.Data.NextToken == nil {
			break
		}
		marker = res.Body.Data.NextToken
	}

	return resources, nil
}

func (p *provider) GrantAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	ramRole, _ := getParametersFromGrant[string](g, parameterRAMRoleKey)
	client, err := p.getOdpsClient(pc, ramRole)
	if err != nil {
		return err
	}

	switch g.Resource.Type {
	case resourceTypeProject:
		project := g.Resource.URN
		securityManager := client.Project(project).SecurityManager()

		addAsProjectMember := false
		var permissions []string
		for _, p := range g.Permissions {
			if p == "member" {
				addAsProjectMember = true
				continue
			}
			permissions = append(permissions, p)
		}

		if addAsProjectMember {
			query := fmt.Sprintf("ADD USER %s", g.AccountID)
			job, err := securityManager.Run(query, true, "")
			if err != nil {
				return fmt.Errorf("failed to add %q as member in %q: %v", g.AccountID, project, err)
			}

			if _, err := job.WaitForSuccess(); err != nil {
				return fmt.Errorf("failed to add %q as member in %q: %v", g.AccountID, project, err)
			}
		}

		if len(permissions) > 0 {
			mcRoles := strings.Join(permissions, ", ")
			query := fmt.Sprintf("GRANT %s TO %s", mcRoles, g.AccountID)
			job, err := securityManager.Run(query, true, "")
			if err != nil {
				return fmt.Errorf("failed to grant %q to %q for %q: %v", mcRoles, project, g.AccountID, err)
			}

			if _, err := job.WaitForSuccess(); err != nil {
				return fmt.Errorf("failed to grant %q to %q for %q: %v", mcRoles, project, g.AccountID, err)
			}
		}
	case resourceTypeTable:
		project := strings.Split(g.Resource.URN, ".")[0]
		securityManager := client.Project(project).SecurityManager()

		actions := strings.Join(g.Permissions, ", ")
		query := fmt.Sprintf("GRANT %s ON TABLE %s TO USER %s", actions, g.Resource.URN, g.AccountID)
		job, err := securityManager.Run(query, true, "")
		if err != nil {
			return fmt.Errorf("failed to grant %q to %q for %q: %v", actions, g.Resource.URN, g.AccountID, err)
		}

		if _, err := job.WaitForSuccess(); err != nil {
			return fmt.Errorf("failed to grant %q to %q for %q: %v", actions, g.Resource.URN, g.AccountID, err)
		}
	default:
		return fmt.Errorf("unsupported resource type: %s", g.Resource.Type)
	}

	return nil
}

func (p *provider) RevokeAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	ramRole, _ := getParametersFromGrant[string](g, parameterRAMRoleKey)
	client, err := p.getOdpsClient(pc, ramRole)
	if err != nil {
		return err
	}

	switch g.Resource.Type {
	case resourceTypeProject:
		project := g.Resource.URN
		securityManager := client.Project(project).SecurityManager()

		revokeFromProjectMember := false
		var permissions []string
		for _, p := range g.Permissions {
			if p == "member" {
				revokeFromProjectMember = true
				continue
			}
			permissions = append(permissions, p)
		}

		if revokeFromProjectMember {
			query := fmt.Sprintf("REMOVE USER %s", g.AccountID)
			job, err := securityManager.Run(query, true, "")
			if err != nil {
				return fmt.Errorf("failed to add %q as member in %q: %v", g.AccountID, project, err)
			}

			if _, err := job.WaitForSuccess(); err != nil {
				return fmt.Errorf("failed to add %q as member in %q: %v", g.AccountID, project, err)
			}
		}

		mcRoles := strings.Join(permissions, ", ")
		query := fmt.Sprintf("REVOKE %s FROM %s", mcRoles, g.AccountID)
		job, err := securityManager.Run(query, true, "")
		if err != nil {
			return fmt.Errorf("failed to revoke %q from %q for %q: %v", mcRoles, project, g.AccountID, err)
		}

		if _, err := job.WaitForSuccess(); err != nil {
			return fmt.Errorf("failed to revoke %q from %q for %q: %v", mcRoles, project, g.AccountID, err)
		}

	case resourceTypeTable:
		project := strings.Split(g.Resource.URN, ".")[0]
		securityManager := client.Project(project).SecurityManager()

		actions := strings.Join(g.Permissions, ", ")
		query := fmt.Sprintf("REVOKE %s ON TABLE %s FROM USER %s", actions, g.Resource.URN, g.AccountID)
		job, err := securityManager.Run(query, true, "")
		if err != nil {
			return fmt.Errorf("failed to revoke %q from %q for %q: %v", actions, g.Resource.URN, g.AccountID, err)
		}

		if _, err := job.WaitForSuccess(); err != nil {
			return fmt.Errorf("failed to revoke %q from %q for %q: %v", actions, g.Resource.URN, g.AccountID, err)
		}
	default:
		return fmt.Errorf("unsupported resource type: %s", g.Resource.Type)
	}

	return nil
}

func (p *provider) getCreds(pc *domain.ProviderConfig) (*credentials, error) {
	cfg := &config{pc}
	creds, err := cfg.getCredentials()
	if err != nil {
		return nil, err
	}
	if err := creds.decrypt(p.encryptor); err != nil {
		return nil, fmt.Errorf("failed to decrypt credentials: %w", err)
	}
	return creds, nil
}

func getClientConfig(providerURN, accountID, accountSecret, regionID, assumeAsRAMRole string) (*openapiv2.Config, error) {
	configV2 := &openapiv2.Config{
		AccessKeyId:     &accountID,
		AccessKeySecret: &accountSecret,
		Endpoint:        &[]string{fmt.Sprintf("maxcompute.%s.aliyuncs.com", regionID)}[0],
	}
	if assumeAsRAMRole != "" {
		stsEndpoint := fmt.Sprintf("sts.%s.aliyuncs.com", regionID)
		configV1 := &openapi.Config{
			AccessKeyId:     configV2.AccessKeyId,
			AccessKeySecret: configV2.AccessKeySecret,
			Endpoint:        &stsEndpoint,
		}
		stsClient, err := sts.NewClient(configV1)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize STS client: %w", err)
		}
		res, err := stsClient.AssumeRole(&sts.AssumeRoleRequest{
			RoleArn:         &assumeAsRAMRole,
			RoleSessionName: &providerURN,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to assume role %q: %w", assumeAsRAMRole, err)
		}
		// TODO: handle refreshing token when the used one is expired

		configV2.AccessKeyId = res.Body.Credentials.AccessKeyId
		configV2.AccessKeySecret = res.Body.Credentials.AccessKeySecret
		configV2.SecurityToken = res.Body.Credentials.SecurityToken
	}

	return configV2, nil
}

func (p *provider) getRestClient(pc *domain.ProviderConfig) (*maxcompute.Client, error) {
	if client, ok := p.restClients[pc.URN]; ok {
		return client, nil
	}

	creds, err := p.getCreds(pc)
	if err != nil {
		return nil, err
	}
	clientConfig, err := getClientConfig(pc.URN, creds.AccessKeyID, creds.AccessKeySecret, creds.RegionID, creds.RAMRole)
	if err != nil {
		return nil, err
	}
	restClient, err := maxcompute.NewClient(clientConfig)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.restClients[pc.URN] = restClient
	p.mu.Unlock()
	return restClient, nil
}

func (p *provider) getOdpsClient(pc *domain.ProviderConfig, overrideRAMRole string) (*odps.Odps, error) {
	usingRAMRole := overrideRAMRole != ""
	if usingRAMRole {
		if client, ok := p.odpsClients[overrideRAMRole]; ok {
			return client, nil
		}
	} else if client, ok := p.odpsClients[pc.URN]; ok {
		return client, nil
	}

	creds, err := p.getCreds(pc)
	if err != nil {
		return nil, err
	}
	ramRole := creds.RAMRole
	if usingRAMRole {
		ramRole = overrideRAMRole
	}

	clientConfig, err := getClientConfig(pc.URN, creds.AccessKeyID, creds.AccessKeySecret, creds.RegionID, ramRole)
	if err != nil {
		return nil, err
	}
	var acc account.Account
	if creds.RAMRole != "" {
		acc = account.NewStsAccount(*clientConfig.AccessKeyId, *clientConfig.AccessKeySecret, *clientConfig.SecurityToken)
	} else {
		acc = account.NewAliyunAccount(*clientConfig.AccessKeyId, *clientConfig.AccessKeySecret)
	}
	endpoint := fmt.Sprintf("http://service.%s.maxcompute.aliyun.com/api", creds.RegionID)
	client := odps.NewOdps(acc, endpoint)

	p.mu.Lock()
	if usingRAMRole {
		p.odpsClients[overrideRAMRole] = client
	} else {
		p.odpsClients[pc.URN] = client
	}
	p.mu.Unlock()
	return client, nil
}

func getParametersFromGrant[T any](g domain.Grant, key string) (T, bool) {
	appealParams, _ := g.Appeal.Details[domain.ReservedDetailsKeyProviderParameters].(map[string]any)
	value, ok := appealParams[key].(T)
	return value, ok
}
