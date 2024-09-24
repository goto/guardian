package shield

import (
	"fmt"

	"github.com/goto/guardian/domain"
)

const (
	ResourceTypeTeam         = "team"
	ResourceTypeProject      = "project"
	ResourceTypeOrganization = "organization"
)

type Metadata struct {
	Email   string `json:"email" mapstructure:"email"`
	Privacy string `json:"privacy" mapstructure:"privacy"`
	Slack   string `json:"slack" mapstructure:"slack"`
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
