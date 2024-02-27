package gitlab

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	pv "github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/utils"
	"github.com/xanzy/go-gitlab"
	"golang.org/x/sync/errgroup"
)

//go:generate mockery --name=encryptor --exported --with-expecter
type encryptor interface {
	domain.Crypto
}

type provider struct {
	pv.UnimplementedClient
	pv.PermissionManager

	typeName  string
	encryptor encryptor
	logger    log.Logger

	clients map[string]*gitlab.Client
	mu      sync.Mutex
}

func NewProvider(typeName string, encryptor encryptor, logger log.Logger) *provider {
	return &provider{
		typeName:  typeName,
		encryptor: encryptor,
		logger:    logger,

		clients: map[string]*gitlab.Client{},
	}
}

func (p *provider) GetType() string {
	return p.typeName
}

func (p *provider) CreateConfig(pc *domain.ProviderConfig) error {
	cfg := &config{pc}
	if err := cfg.validateGitlabSpecificConfig(); err != nil {
		return fmt.Errorf("invalid gitlab config: %w", err)
	}

	// encrypt sensitive config
	creds, err := cfg.getCredentials()
	if err != nil {
		return err
	}
	if err := creds.encrypt(p.encryptor); err != nil {
		return fmt.Errorf("unable to encrypt credentials: %w", err)
	}
	pc.Credentials = creds

	return nil
}

func (p *provider) GetResources(ctx context.Context, pc *domain.ProviderConfig) ([]*domain.Resource, error) {
	client, err := p.getClient(*pc)
	if err != nil {
		return nil, err
	}

	var resources []*domain.Resource
	resourceTypes := pc.GetResourceTypes()

	var mu sync.Mutex
	eg, ctx := errgroup.WithContext(ctx)

	if utils.ContainsString(resourceTypes, resourceTypeGroup) {
		eg.Go(func() error {
			groups, err := fetchResources(ctx,
				func(listOpt gitlab.ListOptions, reqOpts ...gitlab.RequestOptionFunc) ([]*gitlab.Group, *gitlab.Response, error) {
					return client.Groups.ListGroups(&gitlab.ListGroupsOptions{ListOptions: listOpt}, reqOpts...)
				},
				func(g *gitlab.Group) *domain.Resource {
					r := group{*g, pc.Type, pc.URN}.toResource()
					return &r
				},
			)
			if err != nil {
				return fmt.Errorf("unable to fetch groups: %w", err)
			}

			mu.Lock()
			resources = append(resources, groups...)
			mu.Unlock()

			return nil
		})
	}

	if utils.ContainsString(resourceTypes, resourceTypeProject) {
		eg.Go(func() error {
			projects, err := fetchResources(ctx,
				func(listOpt gitlab.ListOptions, reqOpts ...gitlab.RequestOptionFunc) ([]*gitlab.Project, *gitlab.Response, error) {
					return client.Projects.ListProjects(&gitlab.ListProjectsOptions{ListOptions: listOpt}, reqOpts...)
				},
				func(p *gitlab.Project) *domain.Resource {
					r := project{*p, pc.Type, pc.URN}.toResource()
					return &r
				},
			)
			if err != nil {
				return fmt.Errorf("unable to fetch projects: %w", err)
			}

			mu.Lock()
			resources = append(resources, projects...)
			mu.Unlock()

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	return resources, nil
}

func (p *provider) GrantAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	client, err := p.getClient(*pc)
	if err != nil {
		return err
	}

	userID, err := strconv.Atoi(g.AccountID)
	if err != nil {
		return fmt.Errorf("invalid user ID: %q: %w", g.AccountID, err)
	}
	for _, p := range g.Permissions {
		accessLevel, ok := gitlabRoleMapping[p]
		if !ok {
			return fmt.Errorf("invalid grant permission: %q", p)
		}

		switch g.Resource.Type {
		case resourceTypeGroup:
			_, res, err := client.GroupMembers.AddGroupMember(g.Resource.URN, &gitlab.AddGroupMemberOptions{
				UserID:      &userID,
				AccessLevel: &accessLevel,
			}, gitlab.WithContext(ctx))
			if res != nil && res.StatusCode == http.StatusConflict {
				_, _, err = client.GroupMembers.EditGroupMember(g.Resource.URN, userID, &gitlab.EditGroupMemberOptions{
					AccessLevel: &accessLevel,
				})
			}
			if err != nil {
				return err
			}
		case resourceTypeProject:
			_, res, err := client.ProjectMembers.AddProjectMember(g.Resource.URN, &gitlab.AddProjectMemberOptions{
				UserID:      &userID,
				AccessLevel: &accessLevel,
			}, gitlab.WithContext(ctx))
			if res != nil && res.StatusCode == http.StatusConflict {
				_, _, err = client.ProjectMembers.EditProjectMember(g.Resource.URN, userID, &gitlab.EditProjectMemberOptions{
					AccessLevel: &accessLevel,
				})
			}
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("invalid resource type: %q", g.Resource.Type)
		}
	}

	return nil
}

func (p *provider) RevokeAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	client, err := p.getClient(*pc)
	if err != nil {
		return err
	}

	userID, err := strconv.Atoi(g.AccountID)
	if err != nil {
		return fmt.Errorf("invalid user ID: %q: %w", g.AccountID, err)
	}

	var res *gitlab.Response
	switch g.Resource.Type {
	case resourceTypeGroup:
		res, err = client.GroupMembers.RemoveGroupMember(g.Resource.URN, userID, &gitlab.RemoveGroupMemberOptions{}, gitlab.WithContext(ctx))
	case resourceTypeProject:
		res, err = client.ProjectMembers.DeleteProjectMember(g.Resource.URN, userID, gitlab.WithContext(ctx))
	default:
		return fmt.Errorf("invalid resource type: %q", g.Resource.Type)
	}
	if res != nil && res.StatusCode == http.StatusNotFound {
		return nil
	} else if err != nil {
		return fmt.Errorf("unable to revoke access: %w", err)
	}

	return nil
}

func (p *provider) GetRoles(pc *domain.ProviderConfig, resourceType string) ([]*domain.Role, error) {
	return pv.GetRoles(pc, resourceType)
}

func (p *provider) GetAccountTypes() []string {
	return []string{accountTypeGitlabUserID}
}

func (p *provider) IsExclusiveRoleAssignment(context.Context) bool {
	return true
}

func (p *provider) getClient(pc domain.ProviderConfig) (*gitlab.Client, error) {
	if client, ok := p.clients[pc.URN]; ok {
		return client, nil
	}

	cfg := &config{&pc}
	creds, err := cfg.getCredentials()
	if err != nil {
		return nil, err
	}
	if err := creds.decrypt(p.encryptor); err != nil {
		return nil, fmt.Errorf("unable to decrypt credentials: %w", err)
	}

	client, err := gitlab.NewClient(creds.AccessToken, gitlab.WithBaseURL(creds.Host))
	if err != nil {
		return nil, fmt.Errorf("unable to create gitlab client: %w", err)
	}

	p.mu.Lock()
	p.clients[pc.URN] = client
	p.mu.Unlock()
	return client, nil
}
