package gitlab

import (
	"context"
	"fmt"

	"github.com/goto/guardian/domain"
	"github.com/xanzy/go-gitlab"
)

func (p *provider) fetchGroups(ctx context.Context, pc domain.ProviderConfig) ([]*domain.Resource, error) {
	client, err := p.getClient(pc)
	if err != nil {
		return nil, err
	}

	groups, err := pagination[*gitlab.Group](func(opt gitlab.ListOptions) ([]*gitlab.Group, *gitlab.Response, error) {
		return client.Groups.ListGroups(&gitlab.ListGroupsOptions{ListOptions: opt}, gitlab.WithContext(ctx))
	})
	if err != nil {
		return nil, err
	}

	resources := make([]*domain.Resource, len(groups))
	for i, g := range groups {
		gg := group{*g, pc.Type, pc.URN}
		r := gg.toResource()
		resources[i] = &r
	}

	return resources, nil
}

func (p *provider) fetchProjects(ctx context.Context, pc domain.ProviderConfig) ([]*domain.Resource, error) {
	client, err := p.getClient(pc)
	if err != nil {
		return nil, err
	}

	projects, err := pagination(func(opt gitlab.ListOptions) ([]*gitlab.Project, *gitlab.Response, error) {
		return client.Projects.ListProjects(&gitlab.ListProjectsOptions{ListOptions: opt}, gitlab.WithContext(ctx))
	})
	if err != nil {
		return nil, err
	}

	resources := make([]*domain.Resource, len(projects))
	for i, g := range projects {
		pp := project{*g, pc.Type, pc.URN}
		r := pp.toResource()
		resources[i] = &r
	}

	return resources, nil
}

type gitlabResources interface {
	*gitlab.Group | *gitlab.Project
}

func pagination[R gitlabResources](
	fetchPage func(gitlab.ListOptions) ([]R, *gitlab.Response, error),
) ([]R, error) {
	var resources []R

	opt := gitlab.ListOptions{Page: 1, PerPage: 5}
	for {
		pageResources, resp, err := fetchPage(opt)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch resources: %w", err)
		}
		resources = append(resources, pageResources...)

		if resp.CurrentPage >= resp.TotalPages {
			break
		}
		opt.Page = resp.NextPage
	}

	return resources, nil
}
