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
	"github.com/aliyun/aliyun-odps-go-sdk/odps/restclient"
	"github.com/aliyun/aliyun-odps-go-sdk/odps/security"
	"github.com/bearaujus/bptr"
	pv "github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/aliauth"
	"github.com/goto/guardian/pkg/alicatalogapis"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/utils"
	"golang.org/x/net/context"
)

//go:generate mockery --name=encryptor --exported --with-expecter
type encryptor interface {
	domain.Crypto
}

type ODPSClient struct {
	client     *odps.Odps
	authConfig *aliauth.AliAuthConfig
}

type RestClient struct {
	client     *maxcompute.Client
	authConfig *aliauth.AliAuthConfig
}

type CatalogAPIsClient struct {
	client     alicatalogapis.Client
	authConfig *aliauth.AliAuthConfig
}

type provider struct {
	pv.UnimplementedClient
	pv.PermissionManager
	typeName           string
	encryptor          encryptor
	restClients        map[string]RestClient
	odpsClients        map[string]ODPSClient
	catalogAPIsClients map[string]CatalogAPIsClient
	logger             log.Logger
	mu                 sync.Mutex
}

func New(
	typeName string,
	encryptor encryptor,
	logger log.Logger,
) *provider {
	return &provider{
		typeName:           typeName,
		encryptor:          encryptor,
		restClients:        make(map[string]RestClient),
		odpsClients:        make(map[string]ODPSClient),
		catalogAPIsClients: make(map[string]CatalogAPIsClient),

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
			GlobalURN:    utils.GetGlobalURN(sourceName, accountID, resourceTypeProject, *project.Name),
		})
	}

	if slices.Contains(availableResourceTypes, resourceTypeSchema) || slices.Contains(availableResourceTypes, resourceTypeTable) {
		odpsClient, err := p.getOdpsClient(pc, credentials.RAMRole)
		if err != nil {
			return nil, err
		}

		schemaRes := map[string]struct{}{defaultSchemaName: {}}
		err = odpsClient.Project(bptr.ToStringSafe(project.Name)).Schemas().List(func(schema *odps.Schema, err error) {
			if schema == nil {
				return
			}
			schemaRes[schema.Name()] = struct{}{}
		})
		if err != nil {
			return nil, err
		}

		if slices.Contains(availableResourceTypes, resourceTypeSchema) {
			for schemaName := range schemaRes {
				urn := fmt.Sprintf("%s.%s", bptr.ToStringSafe(project.Name), schemaName)
				resources = append(resources, &domain.Resource{
					ProviderType: pc.Type,
					ProviderURN:  pc.URN,
					Type:         resourceTypeSchema,
					URN:          urn,
					Name:         schemaName,
					GlobalURN:    utils.GetGlobalURN(sourceName, accountID, resourceTypeSchema, urn),
				})
			}
		}

		if slices.Contains(availableResourceTypes, resourceTypeTable) {
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
						table.Schema = bptr.FromString(defaultSchemaName)
					}
					urn = fmt.Sprintf("%s.%s.%s", bptr.ToStringSafe(project.Name), bptr.ToStringSafe(table.Schema), bptr.ToStringSafe(table.Name))
					resources = append(resources, &domain.Resource{
						ProviderType: pc.Type,
						ProviderURN:  pc.URN,
						Type:         resourceTypeTable,
						URN:          urn,
						Name:         bptr.ToStringSafe(table.Name),
						GlobalURN:    utils.GetGlobalURN(sourceName, accountID, resourceTypeTable, urn),
					})
				}
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

	switch g.Resource.Type {
	case resourceTypeProject:
		client, err := p.getOdpsClient(pc, ramRole)
		if err != nil {
			return err
		}

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
			query := fmt.Sprintf("ADD USER `%s`", g.AccountID)
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
			query := fmt.Sprintf("GRANT %s TO `%s`", mcRoles, g.AccountID)
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

	case resourceTypeSchema:
		client, err := p.getCatalogAPIsClient(pc, ramRole)
		if err != nil {
			return err
		}

		project := strings.Split(g.Resource.URN, ".")[0]
		schema := g.Resource.Name

		for _, permission := range g.Permissions {
			if _, err = client.RoleBindingSchemaCreate(ctx, &alicatalogapis.RoleBindingSchemaCreateRequest{
				Project:             project,
				Schema:              schema,
				RoleName:            permission,
				Members:             []string{g.AccountID},
				IgnoreAlreadyExists: true,
			}); err != nil {
				return fmt.Errorf("failed to grant schema level access from member %q on %q: %v", g.AccountID, g.Resource.URN, err)
			}
		}

	case resourceTypeTable:
		client, err := p.getOdpsClient(pc, ramRole)
		if err != nil {
			return err
		}

		project := strings.Split(g.Resource.URN, ".")[0]
		securityManager := client.Project(project).SecurityManager()

		actions := strings.Join(g.Permissions, ", ")
		query := fmt.Sprintf("GRANT %s ON TABLE %s TO USER `%s`", actions, g.Resource.URN, g.AccountID)
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

	switch g.Resource.Type {
	case resourceTypeProject:
		client, err := p.getOdpsClient(pc, ramRole)
		if err != nil {
			return err
		}

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
			query := fmt.Sprintf("REMOVE USER `%s`", g.AccountID)
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
			query := fmt.Sprintf("REVOKE %s FROM `%s`", mcRoles, g.AccountID)
			job, err := securityManager.Run(query, true, "")
			if err != nil {
				return fmt.Errorf("failed to revoke %q from %q for %q: %v", mcRoles, project, g.AccountID, err)
			}

			if _, err := job.WaitForSuccess(); err != nil {
				return fmt.Errorf("failed to revoke %q from %q for %q: %v", mcRoles, project, g.AccountID, err)
			}
		}

	case resourceTypeSchema:
		client, err := p.getCatalogAPIsClient(pc, ramRole)
		if err != nil {
			return err
		}

		project := strings.Split(g.Resource.URN, ".")[0]
		schema := g.Resource.Name

		for _, permission := range g.Permissions {
			if err = client.RoleBindingSchemaDelete(ctx, &alicatalogapis.RoleBindingSchemaDeleteRequest{
				Project:         project,
				Schema:          schema,
				RoleName:        permission,
				Members:         []string{g.AccountID},
				IgnoreNotExists: true,
			}); err != nil {
				return fmt.Errorf("failed to revoke schema level access from member %q on %q: %v", g.AccountID, g.Resource.URN, err)
			}
		}

	case resourceTypeTable:
		client, err := p.getOdpsClient(pc, ramRole)
		if err != nil {
			return err
		}

		project := strings.Split(g.Resource.URN, ".")[0]
		securityManager := client.Project(project).SecurityManager()

		actions := strings.Join(g.Permissions, ", ")
		query := fmt.Sprintf("REVOKE %s ON TABLE %s FROM USER `%s`", actions, g.Resource.URN, g.AccountID)
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

	ramRole := p.getRamRole(creds, "")
	cachedClientKey := fmt.Sprintf("%s:%s", creds.AccessKeyID, ramRole)

	if c, exists := p.restClients[cachedClientKey]; exists {
		if c.authConfig.IsConfigValid() {
			return c.client, nil
		}
		p.mu.Lock()
		delete(p.restClients, cachedClientKey)
		p.mu.Unlock()
	}

	authCofig, err := aliauth.NewConfig(creds.AccessKeyID, creds.AccessKeySecret, creds.RegionID, ramRole, pc.URN)
	if err != nil {
		return nil, err
	}

	authCreds, err := authCofig.GetCredentials()
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("maxcompute.%s.aliyuncs.com", creds.RegionID)
	authCreds.Endpoint = &endpoint
	restClient, err := maxcompute.NewClient(authCreds)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.restClients[cachedClientKey] = RestClient{client: restClient, authConfig: authCofig}

	return restClient, nil
}

func (p *provider) getOdpsClient(pc *domain.ProviderConfig, overrideRamRole string) (*odps.Odps, error) {
	creds, err := p.getCreds(pc)
	if err != nil {
		return nil, err
	}

	ramRole := p.getRamRole(creds, overrideRamRole)
	cachedClientKey := fmt.Sprintf("%s:%s", creds.AccessKeyID, ramRole)

	if c, exists := p.odpsClients[cachedClientKey]; exists {
		if c.authConfig.IsConfigValid() {
			return c.client, nil
		}
		p.mu.Lock()
		delete(p.odpsClients, cachedClientKey)
		p.mu.Unlock()
	}

	authConfig, err := aliauth.NewConfig(creds.AccessKeyID, creds.AccessKeySecret, creds.RegionID, ramRole, pc.URN)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("http://service.%s.maxcompute.aliyun.com/api", creds.RegionID)
	client := odps.NewOdps(authConfig.GetAccount(), endpoint)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.odpsClients[cachedClientKey] = ODPSClient{client: client, authConfig: authConfig}

	return client, nil
}

func (p *provider) getCatalogAPIsClient(pc *domain.ProviderConfig, overrideRamRole string) (alicatalogapis.Client, error) {
	creds, err := p.getCreds(pc)
	if err != nil {
		return nil, err
	}

	ramRole := p.getRamRole(creds, overrideRamRole)
	cachedClientKey := fmt.Sprintf("%s:%s", creds.AccessKeyID, ramRole)

	if c, exists := p.catalogAPIsClients[cachedClientKey]; exists {
		if c.authConfig.IsConfigValid() {
			return c.client, nil
		}
		p.mu.Lock()
		delete(p.catalogAPIsClients, cachedClientKey)
		p.mu.Unlock()
	}

	authConfig, err := aliauth.NewConfig(creds.AccessKeyID, creds.AccessKeySecret, creds.RegionID, ramRole, pc.URN)
	if err != nil {
		return nil, err
	}

	authConfigCredentials, err := authConfig.GetCredentials()
	if err != nil {
		return nil, err
	}
	securityToken := bptr.ToStringSafe(authConfigCredentials.SecurityToken)

	var clientOptions []alicatalogapis.ClientOption
	if securityToken != "" {
		clientOptions = append(clientOptions, alicatalogapis.WithSecurityToken(securityToken))
	}

	client, err := alicatalogapis.NewClient(
		bptr.ToStringSafe(authConfigCredentials.AccessKeyId),
		bptr.ToStringSafe(authConfigCredentials.AccessKeySecret),
		creds.RegionID,
		getAccountIDFromRamRole(ramRole),
		clientOptions...,
	)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.catalogAPIsClients[cachedClientKey] = CatalogAPIsClient{client: client, authConfig: authConfig}

	return client, nil
}

func (p *provider) getRamRole(creds *credentials, overrideRamRole string) string {
	var ramRole string
	switch {
	case overrideRamRole != "":
		ramRole = overrideRamRole
	case creds.RAMRole != "":
		ramRole = creds.RAMRole
	}
	return ramRole
}

// getAccountIDFromRamRole expected input format: 'acs:ram::{ACCOUNT-ID}:role/{ROLE-NAME}'
func getAccountIDFromRamRole(ramRole string) string {
	ramRoleParts := strings.Split(ramRole, ":")
	if len(ramRoleParts) != 5 {
		return ""
	}
	return ramRoleParts[3]
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
