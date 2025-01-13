package maxcompute

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"

	maxcompute "github.com/alibabacloud-go/maxcompute-20220104/client"
	"github.com/aliyun/aliyun-odps-go-sdk/odps"
	"github.com/aliyun/aliyun-odps-go-sdk/odps/account"
	"github.com/aliyun/aliyun-odps-go-sdk/odps/restclient"
	"github.com/aliyun/aliyun-odps-go-sdk/odps/security"
	"github.com/bearaujus/bptr"
	pv "github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	sts "github.com/goto/guardian/pkg/stsClient"
	"github.com/goto/guardian/utils"
	"golang.org/x/net/context"

	openapiV2 "github.com/alibabacloud-go/darabonba-openapi/v2/client"
)

//go:generate mockery --name=encryptor --exported --with-expecter
type encryptor interface {
	domain.Crypto
}

type ODPSClient struct {
	client         *odps.Odps
	stsClientExist bool
}

type RestClient struct {
	client         *maxcompute.Client
	stsClientExist bool
}

type provider struct {
	pv.UnimplementedClient
	pv.PermissionManager
	typeName    string
	encryptor   encryptor
	restClients map[string]RestClient
	odpsClients map[string]ODPSClient
	sts         *sts.Sts
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
		restClients: make(map[string]RestClient),
		odpsClients: make(map[string]ODPSClient),
		sts:         sts.NewSTS(),

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
	credentials, err := p.getCreds(pc)
	if err != nil {
		return nil, err
	}
	projectName := credentials.ProjectName

	client, err := p.getRestClient(pc)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize maxcompute rest client: %w", err)
	}

	resources := make([]*domain.Resource, 0)
	availableResourceTypes := pc.GetResourceTypes()

	res, err := client.GetProject(&projectName, &maxcompute.GetProjectRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch project details of %q: %w", projectName, err)
	}
	project := res.Body.Data
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
		odpsClient, err := p.getOdpsClient(pc, credentials.RAMRole)
		if err != nil {
			return nil, err
		}

		schemaRes := map[string]struct{}{"default": {}}
		err = odpsClient.Project(bptr.ToStringSafe(project.Name)).Schemas().List(func(schema *odps.Schema, err error) {
			if schema == nil {
				return
			}
			schemaRes[schema.Name()] = struct{}{}
		})
		if err != nil {
			return nil, err
		}

		for schemaName := range schemaRes {
			var marker *string
			var tableRes []*maxcompute.ListTablesResponseBodyDataTables
			for {
				tmpTableRes, err := client.ListTables(project.Name, &maxcompute.ListTablesRequest{
					Marker:     marker,
					SchemaName: bptr.FromString(schemaName),
				})
				if err != nil {
					return nil, fmt.Errorf("failed to list tables for project '%s' using schema '%s': %w", bptr.ToStringSafe(project.Name), schemaName, err)
				}
				marker = tmpTableRes.Body.Data.Marker

				tableRes = append(tableRes, tmpTableRes.Body.Data.Tables...)
				if bptr.ToStringSafe(marker) == "" {
					break
				}
			}

			for _, table := range tableRes {
				var urn string
				if table.Schema == nil {
					urn = fmt.Sprintf("%s.%s", bptr.ToStringSafe(project.Name), bptr.ToStringSafe(table.Name))
				} else {
					urn = fmt.Sprintf("%s.%s.%s", bptr.ToStringSafe(project.Name), bptr.ToStringSafe(table.Schema), bptr.ToStringSafe(table.Name))
				}
				resources = append(resources, &domain.Resource{
					ProviderType: pc.Type,
					ProviderURN:  pc.URN,
					Type:         resourceTypeTable,
					URN:          urn,
					Name:         bptr.ToStringSafe(table.Name),
					GlobalURN:    utils.GetGlobalURN("maxcompute", accountID, resourceTypeTable, urn),
				})
			}
		}
	}

	return resources, nil
}

func (p *provider) GrantAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	var ramRole string
	if slices.Contains(pc.GetParameterKeys(), parameterRAMRoleKey) {
		r, _, err := getParametersFromGrant[string](g, parameterRAMRoleKey)
		if err != nil {
			return fmt.Errorf("failed to get %q parameter value from grant: %w", parameterRAMRoleKey, err)
		}
		ramRole = r
	}
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
			if p == projectPermissionMember {
				addAsProjectMember = true
				continue
			}
			permissions = append(permissions, p)
		}

		if addAsProjectMember {
			query := fmt.Sprintf("ADD USER %s", g.AccountID)
			job, err := execGrantQuery(securityManager, query)
			if err != nil {
				return fmt.Errorf("failed to add %q as member in %q: %v", g.AccountID, project, err)
			}
			if job != nil {
				if _, err := job.WaitForSuccess(); err != nil {
					return fmt.Errorf("failed to add %q as member in %q: %v", g.AccountID, project, err)
				}
			}
		}

		if len(permissions) > 0 {
			mcRoles := strings.Join(permissions, ", ")
			query := fmt.Sprintf("GRANT %s TO %s", mcRoles, g.AccountID)
			job, err := execGrantQuery(securityManager, query)
			if err != nil {
				return fmt.Errorf("failed to grant %q to %q for %q: %v", mcRoles, project, g.AccountID, err)
			}
			if job != nil {
				if _, err := job.WaitForSuccess(); err != nil {
					return fmt.Errorf("failed to grant %q to %q for %q: %v", mcRoles, project, g.AccountID, err)
				}
			}
		}
	case resourceTypeTable:
		project := strings.Split(g.Resource.URN, ".")[0]
		securityManager := client.Project(project).SecurityManager()

		actions := strings.Join(g.Permissions, ", ")
		query := fmt.Sprintf("GRANT %s ON TABLE %s TO USER %s", actions, g.Resource.Name, g.AccountID)
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
	var ramRole string
	if slices.Contains(pc.GetParameterKeys(), parameterRAMRoleKey) {
		r, _, err := getParametersFromGrant[string](g, parameterRAMRoleKey)
		if err != nil {
			return fmt.Errorf("failed to get %q parameter value from grant: %w", parameterRAMRoleKey, err)
		}
		ramRole = r
	}
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
			if p == projectPermissionMember {
				revokeFromProjectMember = true
				continue
			}
			permissions = append(permissions, p)
		}

		if revokeFromProjectMember {
			query := fmt.Sprintf("REMOVE USER %s", g.AccountID)
			job, err := securityManager.Run(query, true, "")
			if err != nil {
				return fmt.Errorf("failed to remove %q as member in %q: %v", g.AccountID, project, err)
			}

			if _, err := job.WaitForSuccess(); err != nil {
				return fmt.Errorf("failed to remove %q as member in %q: %v", g.AccountID, project, err)
			}
		}

		if len(permissions) > 0 {
			mcRoles := strings.Join(permissions, ", ")
			query := fmt.Sprintf("REVOKE %s FROM %s", mcRoles, g.AccountID)
			job, err := securityManager.Run(query, true, "")
			if err != nil {
				return fmt.Errorf("failed to revoke %q from %q for %q: %v", mcRoles, project, g.AccountID, err)
			}

			if _, err := job.WaitForSuccess(); err != nil {
				return fmt.Errorf("failed to revoke %q from %q for %q: %v", mcRoles, project, g.AccountID, err)
			}
		}
	case resourceTypeTable:
		project := strings.Split(g.Resource.URN, ".")[0]
		securityManager := client.Project(project).SecurityManager()

		actions := strings.Join(g.Permissions, ", ")
		query := fmt.Sprintf("REVOKE %s ON TABLE %s FROM USER %s", actions, g.Resource.Name, g.AccountID)
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

func (p *provider) GetDependencyGrants(ctx context.Context, pd domain.Provider, g domain.Grant) ([]*domain.Grant, error) {
	if g.Resource.ProviderType != "maxcompute" {
		return nil, fmt.Errorf("unsupported provider type: %q", g.Resource.ProviderType)
	}

	var projectName string
	switch g.Resource.Type {
	case resourceTypeProject:
		if !slices.Contains(g.Permissions, projectPermissionMember) {
			projectName = g.Resource.URN
		}
	case resourceTypeTable:
		projectName = strings.Split(g.Resource.URN, ".")[0]
	default:
		return nil, fmt.Errorf("invalid resource type: %q", g.Resource.Type)
	}

	if projectName == "" {
		return nil, nil
	}

	projectMember := &domain.Grant{
		AccountID:   g.AccountID,
		AccountType: g.AccountType,
		Role:        projectPermissionMember,
		Permissions: []string{projectPermissionMember},
		IsPermanent: true,
		Resource: &domain.Resource{
			ProviderType: g.Resource.ProviderType,
			ProviderURN:  g.Resource.ProviderURN,
			Type:         resourceTypeProject,
			URN:          projectName,
		},
	}

	return []*domain.Grant{projectMember}, nil
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

func (p *provider) getRestClient(pc *domain.ProviderConfig) (*maxcompute.Client, error) {
	creds, err := p.getCreds(pc)
	if err != nil {
		return nil, err
	}

	ramRole, stsClientID := p.getRamRoleAndStsClientID("rest", creds, "")
	if restClient, ok := p.getCachedRestClient(ramRole, stsClientID, pc.URN); ok {
		return restClient, nil
	}

	endpoint := fmt.Sprintf("maxcompute.%s.aliyuncs.com", creds.RegionID)
	var clientConfig *openapiV2.Config
	if creds.RAMRole != "" {
		stsClient, err := p.sts.GetSTSClient(stsClientID, creds.AccessKeyID, creds.AccessKeySecret, creds.RegionID)
		if err != nil {
			return nil, err
		}

		clientConfig, err = sts.AssumeRole(stsClient, creds.RAMRole, pc.URN, creds.RegionID)
		if err != nil {
			return nil, err
		}
		clientConfig.Endpoint = &endpoint
	} else {
		clientConfig = &openapiV2.Config{
			AccessKeyId:     &creds.AccessKeyID,
			AccessKeySecret: &creds.AccessKeySecret,
			Endpoint:        &endpoint,
		}
	}

	restClient, err := maxcompute.NewClient(clientConfig)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	if creds.RAMRole != "" {
		p.restClients[creds.RAMRole] = RestClient{client: restClient, stsClientExist: true}
	} else {
		p.restClients[pc.URN] = RestClient{client: restClient}
	}
	p.mu.Unlock()
	return restClient, nil
}

func (p *provider) getOdpsClient(pc *domain.ProviderConfig, ramRoleFromAppeal string) (*odps.Odps, error) {
	creds, err := p.getCreds(pc)
	if err != nil {
		return nil, err
	}

	// getting client from memory cache
	ramRole, stsClientID := p.getRamRoleAndStsClientID("odps", creds, ramRoleFromAppeal)
	if odpsClient, ok := p.getCachedOdpsClient(ramRole, stsClientID, pc.URN); ok {
		return odpsClient, nil
	}

	// initialize new client
	var acc account.Account
	if ramRole != "" {
		stsClient, err := p.sts.GetSTSClient(stsClientID, creds.AccessKeyID, creds.AccessKeySecret, creds.RegionID)
		if err != nil {
			return nil, err
		}

		clientConfig, err := sts.AssumeRole(stsClient, ramRole, pc.URN, creds.RegionID)
		if err != nil {
			return nil, err
		}
		acc = account.NewStsAccount(*clientConfig.AccessKeyId, *clientConfig.AccessKeySecret, *clientConfig.SecurityToken)
	} else {
		acc = account.NewAliyunAccount(creds.AccessKeyID, creds.AccessKeySecret)
	}
	endpoint := fmt.Sprintf("http://service.%s.maxcompute.aliyun.com/api", creds.RegionID)
	client := odps.NewOdps(acc, endpoint)

	p.mu.Lock()
	if ramRoleFromAppeal != "" {
		p.odpsClients[ramRoleFromAppeal] = ODPSClient{client: client, stsClientExist: true}
	} else {
		p.odpsClients[pc.URN] = ODPSClient{client: client}
	}
	p.mu.Unlock()

	return client, nil
}

func (p *provider) getRamRoleAndStsClientID(clientType string, creds *credentials, ramRoleFromAppeal string) (string, string) {
	var ramRole string
	switch {
	case ramRoleFromAppeal != "":
		ramRole = ramRoleFromAppeal
	case creds.RAMRole != "":
		ramRole = creds.RAMRole
	}
	stsClientID := clientType + "-" + ramRole
	return ramRole, stsClientID
}

func (p *provider) getCachedOdpsClient(ramRole, stsClientID, urn string) (*odps.Odps, bool) {
	c, ok := p.odpsClients[ramRole]
	if ramRole != "" && ok && c.stsClientExist && p.sts.IsSTSTokenValid(stsClientID) {
		return c.client, true
	}

	if c, ok := p.odpsClients[urn]; ok {
		return c.client, true
	}

	return nil, false
}

func (p *provider) getCachedRestClient(ramRole, stsClientID, urn string) (*maxcompute.Client, bool) {
	c, ok := p.restClients[ramRole]
	if ramRole != "" && ok && c.stsClientExist && p.sts.IsSTSTokenValid(stsClientID) {
		return c.client, true
	}

	if c, ok := p.restClients[urn]; ok {
		return c.client, true
	}

	return nil, false
}

func getParametersFromGrant[T any](g domain.Grant, key string) (T, bool, error) {
	var value T
	if g.Appeal == nil {
		return value, false, fmt.Errorf("appeal is missing in grant")
	}
	appealParams, _ := g.Appeal.Details[domain.ReservedDetailsKeyProviderParameters].(map[string]any)
	if appealParams == nil {
		return value, false, nil
	}

	value, ok := appealParams[key].(T)
	return value, ok, nil
}

func execGrantQuery(sm security.Manager, query string) (*security.AuthQueryInstance, error) {
	instance, err := sm.Run(query, true, "")
	if err != nil {
		var restErr restclient.HttpError
		if errors.As(err, &restErr) {
			if restErr.StatusCode == http.StatusConflict && restErr.ErrorMessage.ErrorCode == "ObjectAlreadyExists" {
				return nil, nil
			}
		}
		return nil, err
	}

	return instance, nil
}
