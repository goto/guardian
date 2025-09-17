package guardian

import (
	"context"
	"errors"
	"fmt"

	pv "github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/mitchellh/mapstructure"
)

type resourceService interface {
	Find(ctx context.Context, filter domain.ListResourcesFilter) ([]*domain.Resource, error)
}

type provider struct {
	pv.UnimplementedClient
	pv.PermissionManager

	typeName        string
	resourceService resourceService
	logger          log.Logger
}

func NewProvider(
	typeName string,
	resourceService resourceService,
	logger log.Logger,
) *provider {
	return &provider{
		typeName:        typeName,
		resourceService: resourceService,
		logger:          logger,
	}
}

func (p *provider) CreateConfig(pc *domain.ProviderConfig) error {
	cfg := &config{pc}
	if err := cfg.validate(); err != nil {
		return fmt.Errorf("%w: %v", pv.ErrInvalidProviderConfig, err)
	}
	return nil
}

func (p *provider) GetType() string {
	return p.typeName
}

func (p *provider) GetAccountTypes() []string {
	return []string{"user"}
}

func (p *provider) GetRoles(pc *domain.ProviderConfig, resourceType string) ([]*domain.Role, error) {
	return pv.GetRoles(pc, resourceType)
}

func (p *provider) ValidateResource(ctx context.Context, r *domain.Resource) error {
	if r.Type != resourceTypePackage {
		return fmt.Errorf("only resource type %q is supported for provider type %q", resourceTypePackage, providerType)
	}
	if r.URN == "" {
		return fmt.Errorf("resource urn is required")
	}

	var packageInfo *PackageInfo
	if err := mapstructure.Decode(r.Details, &packageInfo); err != nil {
		return fmt.Errorf("failed to decode resource details: %w", err)
	}
	if err := packageInfo.Validate(); err != nil {
		return fmt.Errorf("invalid resource details: %w", err)
	}

	r.GlobalURN = fmt.Sprintf("orn:%s:%s:%s:%s", r.ProviderType, r.ProviderURN, r.Type, r.URN)

	return nil
}

func (p *provider) GrantAccess(ctx context.Context, pc *domain.ProviderConfig, grant domain.Grant) error {
	return nil
}

func (p *provider) RevokeAccess(ctx context.Context, pc *domain.ProviderConfig, grant domain.Grant) error {
	return nil
}

func (p *provider) GetDependencyGrants(ctx context.Context, pd domain.Provider, g domain.Grant) ([]*domain.Grant, error) {
	var dependencies []*domain.Grant

	switch g.Resource.Type {
	case resourceTypePackage:
		pkgGrant := g
		pkgResource := g.Resource
		pkgInfo, err := getPackageInfo(pkgResource)
		if err != nil {
			return nil, fmt.Errorf("failed to get package info: %w", err)
		}

		resources, err := p.resourceService.Find(ctx, domain.ListResourcesFilter{
			// PackageID: packageResource.ID, // TODO: implement package id filter
		})
		if err != nil {
			return nil, err
		}

		for _, resource := range resources {
			var accountConfig *PackageAccountConfig
			for _, g := range pkgInfo.Accounts {
				if g.ProviderType == resource.ProviderType {
					accountConfig = g
					break
				}
			}
			if accountConfig == nil {
				return nil, fmt.Errorf("unable to find account configuration for provider type %q", resource.ProviderType)
			}

			accountType := accountConfig.AccountType

			grantDep := &domain.Grant{
				ResourceID: resource.ID,

				AccountType: accountType,

				AccountID: "", // TODO: resolve dynamically from appeal
				Role:      accountConfig.GrantParameters.Role,

				IsPermanent:          pkgGrant.IsPermanent,
				ExpirationDate:       pkgGrant.ExpirationDate,
				ExpirationDateReason: pkgGrant.ExpirationDateReason,
			}

			dependencies = append(dependencies, grantDep)
		}
	}

	return dependencies, nil
}

func getPackageInfo(r *domain.Resource) (*PackageInfo, error) {
	if r.Details == nil {
		return nil, errors.New("empty package details")
	}

	var pi PackageInfo
	if err := mapstructure.Decode(r.Details, &pi); err != nil {
		return nil, err
	}

	return &pi, nil
}
