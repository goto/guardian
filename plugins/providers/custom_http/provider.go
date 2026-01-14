package custom_http

import (
	"context"
	"fmt"

	pv "github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/mitchellh/mapstructure"
)

type Provider struct {
	pv.UnimplementedClient
	pv.PermissionManager

	typeName string
	Clients  map[string]HTTPClient
	logger   log.Logger
}

func NewProvider(typeName string, logger log.Logger) *Provider {
	return &Provider{
		typeName: typeName,
		Clients:  map[string]HTTPClient{},
		logger:   logger,
	}
}

func (p *Provider) GetType() string {
	return p.typeName
}

func (p *Provider) GetAccountTypes() []string {
	return []string{
		"user",
		"serviceAccount",
	}
}

func (p *Provider) CreateConfig(pc *domain.ProviderConfig) error {
	// Validate provider type
	if pc.Type != "custom_http" {
		return fmt.Errorf("invalid provider type: %s", pc.Type)
	}

	// Validate credentials structure
	var creds Credentials
	if err := mapstructure.Decode(pc.Credentials, &creds); err != nil {
		return fmt.Errorf("invalid provider credentials: %w", err)
	}

	// Validate required credential fields
	if creds.BaseURL == "" {
		return fmt.Errorf("base_url is required in credentials")
	}

	// Validate that we have at least one resource config
	if len(pc.Resources) == 0 {
		return fmt.Errorf("at least one resource configuration is required")
	}

	// Validate that we have the configuration in labels
	// Validate provider configuration
	config := NewConfig(pc)
	if err := config.ParseAndValidate(); err != nil {
		return err
	}

	return nil
}

func (p *Provider) GetResources(ctx context.Context, pc *domain.ProviderConfig) ([]*domain.Resource, error) {
	client, err := p.getClient(pc)
	if err != nil {
		return nil, err
	}

	var allDomainResources []*domain.Resource

	// Fetch resources for each configured resource type
	for _, resourceConfig := range pc.Resources {
		resources, err := client.GetResources(ctx, resourceConfig.Type)
		if err != nil {
			return nil, fmt.Errorf("getting resources of type %s from HTTP API: %w", resourceConfig.Type, err)
		}

		// Convert to domain resources
		for _, res := range resources {
			domainResource := res.ToDomain()
			domainResource.ProviderType = pc.Type
			domainResource.ProviderURN = pc.URN
			domainResource.GlobalURN = fmt.Sprintf("custom_http:%s:%s:%s", pc.URN, res.Type, res.URN)
			allDomainResources = append(allDomainResources, domainResource)
		}
	}

	return allDomainResources, nil
}

func (p *Provider) GetRoles(pc *domain.ProviderConfig, resourceType string) ([]*domain.Role, error) {
	return pv.GetRoles(pc, resourceType)
}

func (p *Provider) GrantAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	client, err := p.getClient(pc)
	if err != nil {
		return err
	}

	resource := &Resource{}
	if err := resource.FromDomain(g.Resource); err != nil {
		return fmt.Errorf("converting resource: %w", err)
	}

	if err := client.GrantAccess(ctx, resource, g.AccountID, g.Role); err != nil {
		return fmt.Errorf("granting access via HTTP API: %w", err)
	}

	p.logger.Info(ctx, "access granted via custom HTTP provider",
		"account_id", g.AccountID,
		"resource_id", g.Resource.ID,
		"role", g.Role)

	return nil
}

func (p *Provider) RevokeAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	client, err := p.getClient(pc)
	if err != nil {
		return err
	}

	resource := &Resource{}
	if err := resource.FromDomain(g.Resource); err != nil {
		return fmt.Errorf("converting resource: %w", err)
	}

	if err := client.RevokeAccess(ctx, resource, g.AccountID, g.Role); err != nil {
		return fmt.Errorf("revoking access via HTTP API: %w", err)
	}

	p.logger.Info(ctx, "access revoked via custom HTTP provider",
		"account_id", g.AccountID,
		"resource_id", g.Resource.ID,
		"role", g.Role)

	return nil
}

func (p *Provider) getClient(pc *domain.ProviderConfig) (HTTPClient, error) {
	if client, exists := p.Clients[pc.URN]; exists {
		return client, nil
	}

	var creds Credentials
	if err := mapstructure.Decode(pc.Credentials, &creds); err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	// Create configuration from credentials resource routes
	config := ProviderConfiguration{
		ResourceTypes: creds.ResourceRoutes,
	}

	client := NewClient(creds, config, p.logger)
	p.Clients[pc.URN] = client

	return client, nil
}
