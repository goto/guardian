package shield

import (
	"context"
	"fmt"
	"net/http"

	"github.com/goto/guardian/domain"
)

//go:generate mockery --name=ShieldClient --exported --with-expecter
type ShieldClient interface {
	GetGroups(ctx context.Context) ([]*Group, error)
	GetResources(ctx context.Context, namespace string) ([]*Resource, error)
	GetProjects(ctx context.Context) ([]*Project, error)
	GetOrganizations(ctx context.Context) ([]*Organization, error)
	GetNamespaces(ctx context.Context) ([]*Namespace, error)
	GrantGroupAccess(ctx context.Context, team *Group, userId string, role string) error
	RevokeGroupAccess(ctx context.Context, team *Group, userId string, role string) error
	GrantProjectAccess(ctx context.Context, project *Project, userId string, role string) error
	RevokeProjectAccess(ctx context.Context, project *Project, userId string, role string) error
	GrantOrganizationAccess(ctx context.Context, organization *Organization, userId string, role string) error
	RevokeOrganizationAccess(ctx context.Context, organization *Organization, userId string, role string) error
	GrantResourceAccess(ctx context.Context, resource *Resource, userId string, role string) error
	RevokeResourceAccess(ctx context.Context, resource *Resource, userId string, role string) error
	GetSelfUser(ctx context.Context, email string) (*User, error)
}

const (
	ResourceTypeTeam         = "team"
	ResourceTypeProject      = "project"
	ResourceTypeOrganization = "organization"
	ResourceTypeResource     = "resource"
)

const (
	groupsEndpoint       = "/admin/v1beta1/groups"
	resourcesEndpoint    = "/admin/v1beta1/resources"
	projectsEndpoint     = "/admin/v1beta1/projects"
	organizationEndpoint = "/admin/v1beta1/organizations"
	namespacesEndpoint   = "/admin/v1beta1/namespaces"
	selfUserEndpoint     = "admin/v1beta1/users/self"
	relationsEndpoint    = "/admin/v1beta1/relations"
	objectEndpoint       = "/admin/v1beta1/object"

	groupsConst        = "groups"
	resourcesConst     = "resources"
	projectsConst      = "projects"
	organizationsConst = "organizations"
	usersConst         = "users"
	namespacesConst    = "namespaces"
	userConst          = "user"
	relationsConst     = "relations"
	relationConst      = "relation"

	userNamespaceConst         = "shield/user"
	groupNamespaceConst        = "shield/group"
	projectNamespaceConst      = "shield/project"
	organizationNamespaceConst = "shield/organization"
	managerRoleConst           = "manager"
)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type ClientConfig struct {
	Host       string `validate:"required,url" mapstructure:"host"`
	AuthHeader string `validate:"required" mapstructure:"auth_header"`
	AuthEmail  string `validate:"required" mapstructure:"auth_email"`
	HTTPClient HTTPClient
}

type Metadata struct {
	Email   string `json:"email" mapstructure:"email"`
	Privacy string `json:"privacy" mapstructure:"privacy"`
	Slack   string `json:"slack" mapstructure:"slack"`
}

type Namespace struct {
	ID   string `json:"id" mapstructure:"id"`
	Name string `json:"name" mapstructure:"name"`
}

type User struct {
	ID    string `json:"id" mapstructure:"id"`
	Name  string `json:"name" mapstructure:"name"`
	Email string `json:"email" mapstructure:"email"`
}

type Group struct {
	ID       string   `json:"id" mapstructure:"id"`
	Name     string   `json:"name" mapstructure:"name"`
	Slug     string   `json:"slug" mapstructure:"slug"`
	OrgId    string   `json:"orgId" mapstructure:"orgId"`
	Metadata Metadata `json:"metadata" mapstructure:"metadata"`
	Admins   []string `json:"admins" mapstructure:"admins"`
}

type Resource struct {
	ID           string       `json:"id" mapstructure:"id"`
	Name         string       `json:"name" mapstructure:"name"`
	URN          string       `json:"urn" mapstructure:"urn"`
	Project      Project      `json:"project" mapstructure:"project"`
	Namespace    Namespace    `json:"namespace" mapstructure:"namespace"`
	User         User         `json:"user" mapstructure:"user"`
	Organization Organization `json:"organization" mapstructure:"organization"`
}

type Role struct {
	ID          string                 `json:"id" mapstructure:"id"`
	Name        string                 `json:"name" mapstructure:"name"`
	Types       []string               `json:"types" mapstructure:"types"`
	Namespace   *string                `json:"namespace" mapstructure:"namespace"`
	Metadata    map[string]interface{} `json:"metadata" mapstructure:"metadata"`
	NamespaceId string                 `json:"namespaceId" mapstructure:"namespaceId"`
}

type GroupRelation struct {
	SubjectType string `json:"subject_type" mapstructure:"subject_type"`
	Role        string `json:"role" mapstructure:"role"`
	User        *User  `json:"user" mapstructure:"user"`
	Group       *Group `json:"group" mapstructure:"group"`
}

type Project struct {
	ID     string   `json:"id" mapstructure:"id"`
	Name   string   `json:"name" mapstructure:"name"`
	Slug   string   `json:"slug" mapstructure:"slug"`
	OrgId  string   `json:"orgId" mapstructure:"orgId"`
	Admins []string `json:"admins" mapstructure:"admins"`
}

type Organization struct {
	ID     string   `json:"id" mapstructure:"id"`
	Name   string   `json:"name" mapstructure:"name"`
	Slug   string   `json:"slug" mapstructure:"slug"`
	Admins []string `json:"admins" mapstructure:"admins"`
}

type Relation struct {
	Id              string `json:"id" mapstructure:"id"`
	ObjectId        string `json:"object_id" mapstructure:"object_id"`
	ObjectNamespace string `json:"object_namespace" mapstructure:"object_namespace"`
	Subject         string `json:"subject" mapstructure:"subject"`
	RoleName        string `json:"role_name" mapstructure:"role_name"`
}

type DeleteRelation struct {
	ObjectId  string `json:"object_id" mapstructure:"object_id"`
	SubjectId string `json:"subject_id" mapstructure:"subject_id"`
	Role      string `json:"role" mapstructure:"role"`
}

func (t *Group) FromDomain(r *domain.Resource) error {
	if r.Type != ResourceTypeTeam {
		return ErrInvalidResourceType
	}

	resourceDetails := r.Details
	if id, ok := resourceDetails["id"].(string); ok {
		t.ID = id
	}
	if orgId, ok := resourceDetails["orgId"].(string); ok {
		t.OrgId = orgId
	}
	t.Name = r.Name

	if resourceDetails["admins"] == nil {
		t.Admins = []string{}
	} else {
		adminsInterface := resourceDetails["admins"].([]interface{})
		admins := make([]string, len(adminsInterface))
		for i, v := range adminsInterface {
			admins[i] = v.(string)
		}
		t.Admins = admins
	}

	metadataInterface := resourceDetails["metadata"].(interface{})
	metadata, ok := metadataInterface.(Metadata)
	if ok {
		t.Metadata = metadata
	}

	return nil
}

func (t *Group) ToDomain() *domain.Resource {
	return &domain.Resource{
		Type: ResourceTypeTeam,
		Name: t.Name,
		URN:  fmt.Sprintf("team:%v", t.ID),
		Details: map[string]interface{}{
			"id":       t.ID,
			"metadata": t.Metadata,
			"orgId":    t.OrgId,
			"admins":   t.Admins,
		},
	}
}

func (p *Project) FromDomain(r *domain.Resource) error {
	if r.Type != ResourceTypeProject {
		return ErrInvalidResourceType
	}

	resourceDetails := r.Details
	if id, ok := resourceDetails["id"].(string); ok {
		p.ID = id
	}
	if orgId, ok := resourceDetails["orgId"].(string); ok {
		p.OrgId = orgId
	}
	p.Name = r.Name

	if resourceDetails["admins"] == nil {
		p.Admins = []string{}
	} else {
		adminsInterface := resourceDetails["admins"].([]interface{})
		admins := make([]string, len(adminsInterface))
		for i, v := range adminsInterface {
			admins[i] = v.(string)
		}
		p.Admins = admins
	}

	return nil
}

func (p *Project) ToDomain() *domain.Resource {
	return &domain.Resource{
		Type: ResourceTypeProject,
		Name: p.Name,
		URN:  fmt.Sprintf("project:%v", p.ID),
		Details: map[string]interface{}{
			"id":     p.ID,
			"orgId":  p.OrgId,
			"admins": p.Admins,
		},
	}
}

func (o *Organization) FromDomain(r *domain.Resource) error {
	if r.Type != ResourceTypeOrganization {
		return ErrInvalidResourceType
	}

	resourceDetails := r.Details
	if id, ok := resourceDetails["id"].(string); ok {
		o.ID = id
	}
	o.Name = r.Name
	if resourceDetails["admins"] == nil {
		o.Admins = []string{}
	} else {
		adminsInterface := resourceDetails["admins"].([]interface{})
		admins := make([]string, len(adminsInterface))
		for i, v := range adminsInterface {
			admins[i] = v.(string)
		}
		o.Admins = admins
	}
	return nil
}

func (o *Organization) ToDomain() *domain.Resource {
	return &domain.Resource{
		Type: ResourceTypeOrganization,
		Name: o.Name,
		URN:  fmt.Sprintf("organization:%v", o.ID),
		Details: map[string]interface{}{
			"id":     o.ID,
			"admins": o.Admins,
		},
	}
}

func (sr *Resource) FromDomain(r *domain.Resource) error {
	resourceDetails := r.Details
	if id, ok := resourceDetails["id"].(string); ok {
		sr.ID = id
	}
	if nsMap, ok := resourceDetails["namespace"].(map[string]interface{}); ok {
		ns := Namespace{}
		if id, ok := nsMap["id"].(string); ok {
			ns.ID = id
		}
		if name, ok := nsMap["name"].(string); ok {
			ns.Name = name
		}
		sr.Namespace = ns
	}
	sr.Name = r.Name
	return nil
}

func (r *Resource) ToDomain() *domain.Resource {
	return &domain.Resource{
		Type: r.Namespace.ID,
		Name: r.Name,
		URN:  fmt.Sprintf("resource:%v", r.ID),
		Details: map[string]interface{}{
			"urn":       r.URN,
			"namespace": r.Namespace,
		},
	}
}
