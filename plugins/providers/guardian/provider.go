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

func (p *provider) GetResources(ctx context.Context, pc *domain.ProviderConfig) ([]*domain.Resource, error) {
	return nil, nil
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
			var grantParams *PackageGrantParameters
			for _, account := range pkgInfo.Accounts {
				if account.ProviderType == resource.ProviderType {
					grantParams = account.GrantParameters
					break
				}
			}

			grantDep := &domain.Grant{
				AccountID:   g.AccountID,
				AccountType: g.AccountType,
				ResourceID:  resource.ID,

				Role: grantParams.Role,

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
