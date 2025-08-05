package shield

import (
	"context"

	pv "github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/utils"
	"github.com/mitchellh/mapstructure"
)

type provider struct {
	pv.UnimplementedClient
	pv.PermissionManager

	typeName string
	Clients  map[string]ShieldClient
	logger   log.Logger
}

func (p *provider) GetAccountTypes() []string {
	return []string{
		AccountTypeUser,
	}
}

func NewProvider(typeName string, logger log.Logger) *provider {
	return &provider{
		typeName: typeName,
		Clients:  map[string]ShieldClient{},
		logger:   logger,
	}
}

func (p *provider) GetType() string {
	return p.typeName
}

func (p *provider) CreateConfig(pc *domain.ProviderConfig) error {
	c := NewConfig(pc)
	var creds Credentials
	if err := mapstructure.Decode(pc.Credentials, &creds); err != nil {
		return err
	}

	client, err := p.GetClient(pc.URN, creds)
	if err != nil {
		return err
	}

	var listOfDynamicResourceType []string

	namespaces, err := client.GetNamespaces(context.Background())
	if err != nil {
		return err
	}

	for _, namespace := range namespaces {
		listOfDynamicResourceType = append(listOfDynamicResourceType, namespace.Name)
	}

	return c.ParseAndValidate(listOfDynamicResourceType)
}

func (p *provider) GetResources(ctx context.Context, pc *domain.ProviderConfig) ([]*domain.Resource, error) {
	var creds Credentials
	if err := mapstructure.Decode(pc.Credentials, &creds); err != nil {
		return nil, err
	}

	client, err := p.GetClient(pc.URN, creds)
	if err != nil {
		return nil, err
	}

	var resourceTypes = make(map[string]bool, 0)
	for _, rc := range pc.Resources {
		resourceTypes[rc.Type] = true
	}

	resources := []*domain.Resource{}

	var teams []*Group
	var projects []*Project
	var organizations []*Organization

	if _, ok := resourceTypes[ResourceTypeTeam]; ok {
		teams, err = client.GetGroups(ctx)
		if err != nil {
			return nil, err
		}
		resources = p.addTeams(pc, teams, resources)
	}

	if _, ok := resourceTypes[ResourceTypeProject]; ok {
		projects, err = client.GetProjects(ctx)
		if err != nil {
			return nil, err
		}
		resources = p.addProjects(pc, projects, resources)
	}

	if _, ok := resourceTypes[ResourceTypeOrganization]; ok {
		organizations, err = client.GetOrganizations(ctx)
		if err != nil {
			return nil, err
		}
		resources = p.addOrganizations(pc, organizations, resources)
	}

	for resourceType := range resourceTypes {
		var shieldResources []*Resource

		if resourceType != ResourceTypeTeam &&
			resourceType != ResourceTypeProject &&
			resourceType != ResourceTypeOrganization {
			shieldResources, err = client.GetResources(ctx, resourceType)
			if err != nil {
				return nil, err
			}
			resources = p.addShieldResources(pc, shieldResources, resources)
		}
	}

	return resources, nil
}

func (p *provider) addTeams(pc *domain.ProviderConfig, teams []*Group, resources []*domain.Resource) []*domain.Resource {
	for _, c := range teams {
		t := c.ToDomain()
		t.ProviderType = pc.Type
		t.ProviderURN = pc.URN
		t.GlobalURN = utils.GetGlobalURN("shield", pc.URN, ResourceTypeTeam, c.ID)
		resources = append(resources, t)
	}

	return resources
}

func (p *provider) addProjects(pc *domain.ProviderConfig, projects []*Project, resources []*domain.Resource) []*domain.Resource {
	for _, c := range projects {
		t := c.ToDomain()
		t.ProviderType = pc.Type
		t.ProviderURN = pc.URN
		t.GlobalURN = utils.GetGlobalURN("shield", pc.URN, ResourceTypeProject, c.ID)
		resources = append(resources, t)
	}
	return resources
}

func (p *provider) addOrganizations(pc *domain.ProviderConfig, organizations []*Organization, resources []*domain.Resource) []*domain.Resource {
	for _, c := range organizations {
		t := c.ToDomain()
		t.ProviderType = pc.Type
		t.ProviderURN = pc.URN
		t.GlobalURN = utils.GetGlobalURN("shield", pc.URN, ResourceTypeOrganization, c.ID)
		resources = append(resources, t)
	}
	return resources
}

func (p *provider) addShieldResources(pc *domain.ProviderConfig, shieldResources []*Resource, resources []*domain.Resource) []*domain.Resource {
	for _, c := range shieldResources {
		t := c.ToDomain()
		t.ProviderType = pc.Type
		t.ProviderURN = pc.URN
		t.GlobalURN = utils.GetGlobalURN("shield", pc.URN, ResourceTypeResource, c.ID)
		resources = append(resources, t)
	}
	return resources
}

func (p *provider) GetClient(providerURN string, credentials Credentials) (ShieldClient, error) {
	if p.Clients[providerURN] != nil {
		return p.Clients[providerURN], nil
	}

	if credentials.ClientVersion == "new" {
		client, err := NewShieldNewClient(&ClientConfig{
			Host:       credentials.Host,
			AuthHeader: credentials.AuthHeader,
			AuthEmail:  credentials.AuthEmail,
		}, p.logger)
		if err != nil {
			return nil, err
		}

		p.Clients[providerURN] = client
		return client, nil
	} else {
		client, err := NewClient(&ClientConfig{
			Host:       credentials.Host,
			AuthHeader: credentials.AuthHeader,
			AuthEmail:  credentials.AuthEmail,
		}, p.logger)
		if err != nil {
			return nil, err
		}
		p.Clients[providerURN] = client
		return client, nil
	}
}

func (p *provider) GetRoles(pc *domain.ProviderConfig, resourceType string) ([]*domain.Role, error) {
	return pv.GetRoles(pc, resourceType)
}

func (p *provider) GrantAccess(ctx context.Context, pc *domain.ProviderConfig, a domain.Grant) error {
	var creds Credentials
	if err := mapstructure.Decode(pc.Credentials, &creds); err != nil {
		return err
	}
	client, err := p.GetClient(pc.URN, creds)
	if err != nil {
		return err
	}

	permissions := a.GetPermissions()

	var user *User
	if user, err = client.GetSelfUser(ctx, a.AccountID); err != nil {
		return nil
	}

	switch a.Resource.Type {
	case ResourceTypeTeam:
		t := new(Group)
		if err := t.FromDomain(a.Resource); err != nil {
			return err
		}
		for _, p := range permissions {
			if err := client.GrantGroupAccess(ctx, t, user.ID, p); err != nil {
				return err
			}
		}
		return nil
	case ResourceTypeProject:
		pj := new(Project)
		if err := pj.FromDomain(a.Resource); err != nil {
			return err
		}
		for _, p := range permissions {
			if err := client.GrantProjectAccess(ctx, pj, user.ID, p); err != nil {
				return err
			}
		}
		return nil
	case ResourceTypeOrganization:
		o := new(Organization)
		if err := o.FromDomain(a.Resource); err != nil {
			return err
		}
		for _, p := range permissions {
			if err := client.GrantOrganizationAccess(ctx, o, user.ID, p); err != nil {
				return err
			}
		}
		return nil
	default:
		r := new(Resource)
		if err := r.FromDomain(a.Resource); err != nil {
			return err
		}
		for _, p := range permissions {
			if err := client.GrantResourceAccess(ctx, r, user.ID, p); err != nil {
				return err
			}
		}
		return nil
	}
}

func (p *provider) RevokeAccess(ctx context.Context, pc *domain.ProviderConfig, a domain.Grant) error {
	var creds Credentials
	if err := mapstructure.Decode(pc.Credentials, &creds); err != nil {
		return err
	}
	client, err := p.GetClient(pc.URN, creds)
	if err != nil {
		return err
	}

	permissions := a.GetPermissions()

	var user *User
	if user, err = client.GetSelfUser(ctx, a.AccountID); err != nil {
		return nil
	}

	switch a.Resource.Type {
	case ResourceTypeTeam:
		t := new(Group)
		if err := t.FromDomain(a.Resource); err != nil {
			return err
		}
		for _, p := range permissions {
			if err := client.RevokeGroupAccess(ctx, t, user.ID, p); err != nil {
				return err
			}
		}

		return nil
	case ResourceTypeProject:
		pj := new(Project)
		if err := pj.FromDomain(a.Resource); err != nil {
			return err
		}
		for _, p := range permissions {
			if err := client.RevokeProjectAccess(ctx, pj, user.ID, p); err != nil {
				return err
			}
		}

		return nil
	case ResourceTypeOrganization:
		o := new(Organization)
		if err := o.FromDomain(a.Resource); err != nil {
			return err
		}
		for _, p := range permissions {
			if err := client.RevokeOrganizationAccess(ctx, o, user.ID, p); err != nil {
				return err
			}
		}
		return nil
	default:
		r := new(Resource)
		if err := r.FromDomain(a.Resource); err != nil {
			return err
		}
		for _, p := range permissions {
			if err := client.RevokeResourceAccess(ctx, r, user.ID, p); err != nil {
				return err
			}
		}
		return nil
	}
}
