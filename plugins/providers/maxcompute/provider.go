package maxcompute

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	maxcompute "github.com/alibabacloud-go/maxcompute-20220104/client"
	"github.com/aliyun/aliyun-odps-go-sdk/odps"
	"github.com/bearaujus/bworker/pool"
	pv "github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/alicatalogapis"
	"github.com/goto/guardian/pkg/aliclientmanager"
	"github.com/goto/guardian/pkg/log"
	sliceshelper "github.com/goto/guardian/pkg/slices"
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
	logger      log.Logger
	mu          *sync.Mutex
	concurrency int

	restClientsCache        map[string]*aliclientmanager.Manager[*maxcompute.Client]
	odpsClientsCache        map[string]*aliclientmanager.Manager[*odps.Odps]
	catalogAPIsClientsCache map[string]*aliclientmanager.Manager[alicatalogapis.Client]
}

func New(
	typeName string,
	encryptor encryptor,
	logger log.Logger,
) *provider {
	return &provider{
		typeName:                typeName,
		encryptor:               encryptor,
		logger:                  logger,
		mu:                      &sync.Mutex{},
		concurrency:             20,
		restClientsCache:        make(map[string]*aliclientmanager.Manager[*maxcompute.Client]),
		odpsClientsCache:        make(map[string]*aliclientmanager.Manager[*odps.Odps]),
		catalogAPIsClientsCache: make(map[string]*aliclientmanager.Manager[alicatalogapis.Client]),
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
	var resources = make([]*domain.Resource, 0)
	var availableResourceTypes = pc.GetResourceTypes()
	if !sliceshelper.GenericsSliceContainsOne(availableResourceTypes, resourceTypeProject, resourceTypeSchema, resourceTypeTable) {
		return resources, nil
	}

	project, accountId, err := p.getProject(ctx, pc)
	if err != nil {
		return nil, err
	}

	if sliceshelper.GenericsSliceContainsOne(availableResourceTypes, resourceTypeSchema, resourceTypeTable) {
		project.Children, err = p.getSchemasFromProject(ctx, pc, "", accountId, project)
		if err != nil {
			return nil, err
		}
	}

	if sliceshelper.GenericsSliceContainsOne(availableResourceTypes, resourceTypeTable) {
		var errW error
		var w = pool.NewBWorkerPool(p.concurrency, pool.WithError(&errW))
		defer w.Shutdown()
		for i, schema := range project.Children {
			i := i
			schema := schema
			w.Do(func() error {
				tables, err := p.getTablesFromSchema(ctx, pc, "", accountId, project, schema)
				if err != nil {
					return err
				}
				p.mu.Lock()
				project.Children[i].Children = tables
				p.mu.Unlock()
				return nil
			})
		}
		w.Wait()
		if errW != nil {
			return nil, errW
		}
	}

	// perform resources mapping (in-order)
	switch {
	case sliceshelper.GenericsSliceContainsAll(availableResourceTypes, resourceTypeProject, resourceTypeSchema, resourceTypeTable) ||
		sliceshelper.GenericsSliceContainsAll(availableResourceTypes, resourceTypeProject, resourceTypeSchema):
		resources = append(resources, project)

	case sliceshelper.GenericsSliceContainsAll(availableResourceTypes, resourceTypeProject, resourceTypeTable):
		for _, schema := range project.Children {
			resources = append(resources, schema.Children...) // add tables individually
		}
		project.Children = nil // remove schemas from project children
		resources = append(resources, project)

	case sliceshelper.GenericsSliceContainsAll(availableResourceTypes, resourceTypeSchema, resourceTypeTable):
		resources = append(resources, project.Children...)

	case slices.Contains(availableResourceTypes, resourceTypeProject):
		resources = append(resources, project)

	case slices.Contains(availableResourceTypes, resourceTypeSchema):
		resources = append(resources, project.Children...)

	case slices.Contains(availableResourceTypes, resourceTypeTable):
		for _, schema := range project.Children {
			resources = append(resources, schema.Children...) // add tables individually
		}
	}
	return resources, nil
}

func (p *provider) GrantAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	var overrideRAMRole string
	if slices.Contains(pc.GetParameterKeys(), parameterRAMRoleKey) {
		r, _, err := getParametersFromGrant[string](g, parameterRAMRoleKey)
		if err != nil {
			return fmt.Errorf("failed to get %q parameter value from grant: %w", parameterRAMRoleKey, err)
		}
		overrideRAMRole = r
	}

	switch g.Resource.Type {
	case resourceTypeProject:
		project := g.Resource.URN

		var addAsProjectMember bool
		var permissions []string
		for _, permission := range g.Permissions {
			if permission == projectPermissionMember {
				addAsProjectMember = true
				continue
			}
			permissions = append(permissions, permission)
		}

		if addAsProjectMember {
			if err := p.addMemberToProject(ctx, pc, overrideRAMRole, project, g.AccountID); err != nil {
				return err
			}
		}

		if err := p.validateProjectRole(ctx, pc, overrideRAMRole, project, permissions...); err != nil {
			return err
		}

		if err := p.grantProjectRolesToMember(ctx, pc, overrideRAMRole, project, g.AccountID, permissions...); err != nil {
			return err
		}

	case resourceTypeSchema:
		client, err := p.getCatalogAPIsClient(pc, overrideRAMRole)
		if err != nil {
			return err
		}

		project := strings.Split(g.Resource.URN, ".")[0]
		schema := g.Resource.Name

		for _, permission := range g.Permissions {
			if _, err = client.RoleBindingSchemaCreate(ctx, &alicatalogapis.RoleBindingSchemaCreateRequest{
				Project:  project,
				Schema:   schema,
				RoleName: permission,
				Members:  []string{g.AccountID},
			}); err != nil {
				return fmt.Errorf("fail to grant schema roles at '%s.%s': %w", project, schema, err)
			}
		}

		schemaDefaultRoleName, err := p.getSchemaDefaultRoleName(pc)
		if err != nil {
			return err
		}

		if schemaDefaultRoleName != "" {
			if _, err = client.RoleBindingProjectCreate(ctx, &alicatalogapis.RoleBindingProjectCreateRequest{
				Project:  project,
				RoleName: schemaDefaultRoleName,
				Members:  []string{g.AccountID},
			}); err != nil {
				return fmt.Errorf("fail to grant schema default roles at '%s.%s': %w", project, schema, err)
			}
		}

	case resourceTypeTable:
		resourceURNSplit := strings.Split(g.Resource.URN, ".")
		project := resourceURNSplit[0]
		schema := resourceURNSplit[1]
		table := g.Resource.Name
		if err := p.grantTableRolesToMember(ctx, pc, overrideRAMRole, project, schema, table, g.AccountID, g.Permissions...); err != nil {
			return err
		}

	default:
		return fmt.Errorf("unsupported resource type: %s", g.Resource.Type)
	}

	return nil
}

func (p *provider) RevokeAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	var overrideRAMRole string
	if slices.Contains(pc.GetParameterKeys(), parameterRAMRoleKey) {
		r, _, err := getParametersFromGrant[string](g, parameterRAMRoleKey)
		if err != nil {
			return fmt.Errorf("failed to get %q parameter value from grant: %w", parameterRAMRoleKey, err)
		}
		overrideRAMRole = r
	}

	switch g.Resource.Type {
	case resourceTypeProject:
		project := g.Resource.URN

		revokeFromProjectMember := false
		var permissions []string
		for _, permission := range g.Permissions {
			if permission == projectPermissionMember {
				revokeFromProjectMember = true
				continue
			}
			permissions = append(permissions, permission)
		}

		if revokeFromProjectMember {
			if err := p.removeMemberFromProject(ctx, pc, overrideRAMRole, project, g.AccountID); err != nil {
				return err
			}
		}

		if err := p.validateProjectRole(ctx, pc, overrideRAMRole, project, permissions...); err != nil {
			return err
		}

		if err := p.revokeProjectRolesFromMember(ctx, pc, overrideRAMRole, project, g.AccountID, permissions...); err != nil {
			return err
		}

	case resourceTypeSchema:
		client, err := p.getCatalogAPIsClient(pc, overrideRAMRole)
		if err != nil {
			return err
		}

		project := strings.Split(g.Resource.URN, ".")[0]
		schema := g.Resource.Name

		for _, permission := range g.Permissions {
			if err = client.RoleBindingSchemaDelete(ctx, &alicatalogapis.RoleBindingSchemaDeleteRequest{
				Project:  project,
				Schema:   schema,
				RoleName: permission,
				Members:  []string{g.AccountID},
			}); err != nil {
				return fmt.Errorf("fail to revoke schema roles from '%s.%s': %w", project, schema, err)
			}
		}

	case resourceTypeTable:
		resourceURNSplit := strings.Split(g.Resource.URN, ".")
		project := resourceURNSplit[0]
		schema := resourceURNSplit[1]
		table := g.Resource.Name
		if err := p.revokeTableRolesFromMember(ctx, pc, overrideRAMRole, project, schema, table, g.AccountID, g.Permissions...); err != nil {
			return err
		}

	default:
		return fmt.Errorf("unsupported resource type: %s", g.Resource.Type)
	}

	return nil
}

func (p *provider) GetDependencyGrants(ctx context.Context, pd domain.Provider, g domain.Grant) ([]*domain.Grant, error) {
	if g.Resource.ProviderType != sourceName {
		return nil, fmt.Errorf("unsupported provider type: %q", g.Resource.ProviderType)
	}

	var projectName string
	switch g.Resource.Type {
	case resourceTypeProject:
		if !slices.Contains(g.Permissions, projectPermissionMember) {
			projectName = g.Resource.URN
		}
	case resourceTypeSchema:
		fallthrough
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

func (p *provider) getSchemaDefaultRoleName(pc *domain.ProviderConfig) (string, error) {
	creds, err := p.getCreds(pc)
	if err != nil {
		return "", err
	}
	return creds.SchemaDefaultPolicy, nil
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
