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
	"github.com/goto/guardian/pkg/opentelemetry/otelhttpclient"
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

	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(20)

	var mu sync.Mutex
	var resources []*domain.Resource
	resourceTypes := pc.GetResourceTypes()

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
		p.logger.Error(ctx, "unable to fetch groups", "provider_urn", pc.URN, "error", err)
		return nil, fmt.Errorf("unable to fetch groups: %w", err)
	}

	for _, group := range groups {
		group := group
		eg.Go(func() error {
			if utils.ContainsString(resourceTypes, resourceTypeProject) {
				projects, err := fetchResources(ctx,
					func(listOpt gitlab.ListOptions, reqOpts ...gitlab.RequestOptionFunc) ([]*gitlab.Project, *gitlab.Response, error) {
						falseBool := false
						return client.Groups.ListGroupProjects(
							group.URN,
							&gitlab.ListGroupProjectsOptions{
								ListOptions: listOpt,
								WithShared:  &falseBool,
							},
							reqOpts...,
						)
					},
					func(p *gitlab.Project) *domain.Resource {
						r := project{*p, pc.Type, pc.URN}.toResource()
						return &r
					},
				)
				if err != nil {
					p.logger.Error(ctx, "unable to fetch projects under a group", "provider_urn", pc.URN, "group_id", group.URN, "error", err)
					return fmt.Errorf("unable to fetch projects under group %q: %w", group.URN, err)
				}

				if utils.ContainsString(resourceTypes, resourceTypeGroup) {
					group.Children = projects
				} else {
					mu.Lock()
					resources = append(resources, projects...)
					mu.Unlock()
				}
			}

			// TODO: handle group <> sub-groups hierarchy
			if utils.ContainsString(resourceTypes, resourceTypeGroup) {
				mu.Lock()
				resources = append(resources, group)
				mu.Unlock()
			}
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

	if len(g.Permissions) != 1 {
		return fmt.Errorf("unexpected number of permissions: %d", len(g.Permissions))
	}
	accessLevel, ok := gitlabRoleMapping[g.Permissions[0]]
	if !ok {
		return fmt.Errorf("invalid grant permission: %q", g.Permissions[0])
	}

	empty := ""
	switch g.Resource.Type {
	case resourceTypeGroup:
		_, res, err := client.GroupMembers.AddGroupMember(g.Resource.URN, &gitlab.AddGroupMemberOptions{
			UserID:      &userID,
			AccessLevel: &accessLevel,
		}, gitlab.WithContext(ctx))
		if res != nil && res.StatusCode == http.StatusConflict {
			_, _, err = client.GroupMembers.EditGroupMember(g.Resource.URN, userID, &gitlab.EditGroupMemberOptions{
				AccessLevel: &accessLevel,
				ExpiresAt:   &empty,
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
				ExpiresAt:   &empty,
			})
		}
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid resource type: %q", g.Resource.Type)
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

	if len(g.Permissions) != 1 {
		return fmt.Errorf("unexpected number of permissions: %d", len(g.Permissions))
	}
	accessLevel, ok := gitlabRoleMapping[g.Permissions[0]]
	if !ok {
		return fmt.Errorf("invalid grant permission: %q", g.Permissions[0])
	}

	var res *gitlab.Response
	switch g.Resource.Type {
	case resourceTypeGroup:
		var member *gitlab.GroupMember
		member, res, err = client.GroupMembers.GetGroupMember(g.Resource.URN, userID, gitlab.WithContext(ctx))
		if member != nil && member.AccessLevel == accessLevel {
			trueBool := true
			res, err = client.GroupMembers.RemoveGroupMember(g.Resource.URN, userID, &gitlab.RemoveGroupMemberOptions{SkipSubresources: &trueBool}, gitlab.WithContext(ctx))
		}
	case resourceTypeProject:
		var member *gitlab.ProjectMember
		member, res, err = client.ProjectMembers.GetProjectMember(g.Resource.URN, userID, gitlab.WithContext(ctx))
		if member != nil && member.AccessLevel == accessLevel {
			res, err = client.ProjectMembers.DeleteProjectMember(g.Resource.URN, userID, gitlab.WithContext(ctx))
		}
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

	gitlabHTTPClient := otelhttpclient.New("GitlabClient", nil)
	client, err := gitlab.NewClient(creds.AccessToken, gitlab.WithBaseURL(creds.Host), gitlab.WithHTTPClient(gitlabHTTPClient))
	if err != nil {
		return nil, fmt.Errorf("unable to create gitlab client: %w", err)
	}

	p.mu.Lock()
	p.clients[pc.URN] = client
	p.mu.Unlock()
	return client, nil
}
