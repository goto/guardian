package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/goto/guardian/domain"
)

func GetRoles(pc *domain.ProviderConfig, resourceType string) ([]*domain.Role, error) {
	for _, r := range pc.Resources {
		if r.Type == resourceType {
			return r.Roles, nil
		}
	}

	return nil, ErrInvalidResourceType
}

type PermissionManager struct{}

func (m PermissionManager) GetPermissions(pc *domain.ProviderConfig, resourceType, role string) ([]interface{}, error) {
	for _, rc := range pc.Resources {
		if rc.Type != resourceType {
			continue
		}
		for _, r := range rc.Roles {
			if r.ID == role {
				if r.Permissions == nil {
					return make([]interface{}, 0), nil
				}
				return r.Permissions, nil
			}
		}
		return nil, ErrInvalidRole
	}
	return nil, ErrInvalidResourceType
}

func normalizeDetails(details map[string]interface{}) (map[string]interface{}, error) {
	jsonData, err := json.Marshal(details)
	if err != nil {
		return nil, err
	}

	var normalized map[string]interface{}
	if err := json.Unmarshal(jsonData, &normalized); err != nil {
		return nil, err
	}

	return normalized, nil
}

func compareResource(existingResource, newResource domain.Resource) (bool, string) {
	opts := cmp.Options{
		cmpopts.IgnoreFields(domain.Resource{}, "ID", "CreatedAt", "UpdatedAt", "ParentID", "Children"),
		cmpopts.EquateEmpty(),
	}
	existingResource.Details, _ = normalizeDetails(existingResource.Details)
	newResource.Details, _ = normalizeDetails(newResource.Details)
	diff := cmp.Diff(existingResource, newResource, opts)
	return diff != "", diff
}

type UnimplementedClient struct{}

func (c *UnimplementedClient) CreateConfig(*domain.ProviderConfig) error {
	return fmt.Errorf("CreateConfig %w", ErrUnimplementedMethod)
}

func (c *UnimplementedClient) GetResources(*domain.ProviderConfig) ([]*domain.Resource, error) {
	return nil, fmt.Errorf("GetResources %w", ErrUnimplementedMethod)
}

func (c *UnimplementedClient) GrantAccess(*domain.ProviderConfig, *domain.Appeal) error {
	return fmt.Errorf("GrantAccess %w", ErrUnimplementedMethod)
}

func (c *UnimplementedClient) RevokeAccess(*domain.ProviderConfig, *domain.Appeal) error {
	return fmt.Errorf("RevokeAccess %w", ErrUnimplementedMethod)
}

func (c *UnimplementedClient) GetRoles(*domain.ProviderConfig, string) ([]*domain.Role, error) {
	return nil, fmt.Errorf("GetRoles %w", ErrUnimplementedMethod)
}

func (c *UnimplementedClient) ListAccess(context.Context, domain.ProviderConfig, []*domain.Resource) (domain.MapResourceAccess, error) {
	return nil, fmt.Errorf("ListAccess %w", ErrUnimplementedMethod)
}
