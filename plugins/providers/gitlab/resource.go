package gitlab

import (
	"strconv"

	"github.com/goto/guardian/core/resource"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/utils"
	"github.com/xanzy/go-gitlab"
)

type group struct {
	gitlab.Group
	providerType string
	providerURN  string
}

func (g group) toResource() domain.Resource {
	strID := strconv.Itoa(g.ID)
	return domain.Resource{
		ProviderType: g.providerType,
		ProviderURN:  g.providerURN,
		Type:         resourceTypeGroup,
		URN:          strID,
		GlobalURN:    utils.GetGlobalURN("gitlab", g.providerURN, resourceTypeGroup, strID),
		Name:         g.FullName,
		Details: map[string]interface{}{
			resource.ReservedDetailsKeyMetadata: map[string]interface{}{
				"description": g.Description,
				"path":        g.Path,
				"full_path":   g.FullPath,
				"name":        g.Name,
				"full_name":   g.FullName,
				"web_url":     g.WebURL,
				"parent_id":   g.ParentID,
				"visibility":  g.Visibility,
			},
		},
	}
}

type project struct {
	gitlab.Project
	providerType string
	providerURN  string
}

func (p project) toResource() domain.Resource {
	strID := strconv.Itoa(p.ID)
	return domain.Resource{
		ProviderType: p.providerType,
		ProviderURN:  p.providerURN,
		Type:         resourceTypeProject,
		URN:          strID,
		GlobalURN:    utils.GetGlobalURN("gitlab", p.providerURN, resourceTypeProject, strID),
		Name:         p.NameWithNamespace,
		Details: map[string]interface{}{
			resource.ReservedDetailsKeyMetadata: map[string]interface{}{
				"description":         p.Description,
				"path":                p.Path,
				"path_with_namespace": p.PathWithNamespace,
				"name":                p.Name,
				"name_with_namespace": p.NameWithNamespace,
				"web_url":             p.WebURL,
				"visibility":          p.Visibility,
				"archived":            p.Archived,
				"namespace_id":        p.Namespace.ID,
			},
		},
	}
}
