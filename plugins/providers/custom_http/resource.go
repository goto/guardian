package custom_http

import (
	"github.com/goto/guardian/domain"
)

const (
	ResourceTypeHTTPResource = "http_resource"
)

type Resource struct {
	ID      string                 `json:"id"`
	Name    string                 `json:"name"`
	URN     string                 `json:"urn"`
	Details map[string]interface{} `json:"details"`
}

func (r *Resource) ToDomain() *domain.Resource {
	return &domain.Resource{
		ID:      r.ID,
		Name:    r.Name,
		URN:     r.URN,
		Type:    ResourceTypeHTTPResource,
		Details: r.Details,
	}
}

func (r *Resource) FromDomain(res *domain.Resource) error {
	r.ID = res.ID
	r.Name = res.Name
	r.URN = res.URN
	r.Details = res.Details
	return nil
}
