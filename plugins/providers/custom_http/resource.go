package custom_http

import (
	"fmt"

	"github.com/goto/guardian/domain"
)

const (
	ResourceTypeHTTPResource = "http_resource"
)

type Resource struct {
	ID      string                 `json:"id"`
	Name    string                 `json:"name"`
	URN     string                 `json:"urn"`
	Type    string                 `json:"type"`
	Details map[string]interface{} `json:"details"`
}

func (r *Resource) ToDomain() *domain.Resource {
	return &domain.Resource{
		ID:       r.ID,
		Name:     r.Name,
		URN:      fmt.Sprintf("custom_http:%s:%s", r.Type, r.ID),
		Type:     r.Type,
		Details:  r.Details,
		Children: []*domain.Resource{},
	}
}

func (r *Resource) String() string {
	return fmt.Sprintf("Resource{ID: %s, Name: %s, Type: %s}", r.ID, r.Name, r.Type)
}

func (r *Resource) FromDomain(res *domain.Resource) error {
	r.ID = res.ID
	r.Name = res.Name
	r.URN = res.URN
	r.Type = res.Type
	r.Details = res.Details
	return nil
}
