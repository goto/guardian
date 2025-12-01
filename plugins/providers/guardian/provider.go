package guardian

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mitchellh/mapstructure"

	pv "github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
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
	return validAccountTypes
}

func (p *provider) GetRoles(pc *domain.ProviderConfig, resourceType string) ([]*domain.Role, error) {
	return pv.GetRoles(pc, resourceType)
}

func (p *provider) ValidateAppeal(ctx context.Context, a *domain.Appeal) error {
	if a.Resource == nil {
		return errors.New("nil appeal resource")
	}

	packageID := a.ResourceID
	if packageID == "" {
		packageID = a.Resource.ID
	}

	switch a.Resource.Type {
	case resourceTypePackage:
		switch a.Role {
		case accountTypeBot:
			// TODO add validation for bot user if required

		case accountTypeUser:
			var err error
			var resources []*domain.Resource
			var pkgInfo *PackageInfo
			var requestorAccounts []*RequestorAccount

			resources, err = p.getGrantableResources(ctx, packageID)
			if err != nil {
				return fmt.Errorf("failed to get grantable resources: %w", err)
			}
			providerTypes := getUniqueProviderTypes(resources)

			pkgInfo, err = getPackageInfo(a.Resource)
			if err != nil {
				return fmt.Errorf("unable to get package info: %w", err)
			}

			requestorAccounts, err = getRequestorAccounts(a)
			if err != nil {
				return fmt.Errorf("invalid appeal parameters: %w", err)
			}

			for _, requiredProviderType := range providerTypes {
				var isAccountTypeFound bool
				for _, accountConfig := range pkgInfo.Accounts {
					if accountConfig.ProviderType != requiredProviderType {
						continue
					}
					isAccountTypeFound = true

					requiredAccountType := accountConfig.AccountType
					var isAccountIDFound bool
					for _, ra := range requestorAccounts {
						if ra.ProviderType == requiredProviderType && ra.AccountType == requiredAccountType && ra.AccountID != "" {
							isAccountIDFound = true
							break
						}
					}
					if !isAccountIDFound {
						return fmt.Errorf("details.%s.%s.account_id is required", domain.ReservedDetailsKeyProviderParameters, providerParameterKeyAccounts)
					}
				}
				if !isAccountTypeFound {
					return fmt.Errorf("invalid package config: unable to find required account type for provider type %q", requiredProviderType)
				}
			}
		}
	}

	return nil
}

func (p *provider) ValidateResourceIdentifiers(ctx context.Context, r *domain.Resource) error {
	if strings.HasPrefix(r.Type, resourceTypePackage) {
		return fmt.Errorf("only resource type %q is supported for provider type %q", resourceTypePackage, providerType)
	}
	if r.URN == "" {
		return fmt.Errorf("resource urn is required")
	}

	r.GlobalURN = fmt.Sprintf("orn:%s:%s:%s:%s", r.ProviderType, r.ProviderURN, r.Type, r.URN)

	return nil
}

func (p *provider) ValidateResourceDetails(ctx context.Context, r *domain.Resource) error {
	var packageInfo *PackageInfo
	if err := mapstructure.Decode(r.Details, &packageInfo); err != nil {
		return fmt.Errorf("failed to decode resource details: %w", err)
	}
	if err := packageInfo.Validate(); err != nil {
		return fmt.Errorf("invalid resource details: %w", err)
	}
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
		switch g.AccountType {
		case accountTypeBot:
			// TODO append dependency grant(s) for bot user to variable 'dependencies' if required

		case accountTypeUser:
			pkgGrant := g
			pkgResource := g.Resource
			pkgInfo, err := getPackageInfo(pkgResource)
			if err != nil {
				return nil, fmt.Errorf("failed to get package info: %w", err)
			}

			requestorAccounts, err := getRequestorAccounts(g.Appeal)
			if err != nil {
				return nil, fmt.Errorf("failed to get requestor accounts: %w", err)
			}

			resources, err := p.getGrantableResources(ctx, pkgResource.ID)
			if err != nil {
				return nil, fmt.Errorf("failed to get grantable resources: %w", err)
			}

			for _, resource := range resources {
				var pkgAccountConfig *PackageAccountConfig
				for _, a := range pkgInfo.Accounts {
					if a.ProviderType == resource.ProviderType {
						pkgAccountConfig = a
						break
					}
				}
				if pkgAccountConfig == nil {
					return nil, fmt.Errorf("unable to find account configuration for provider type %q", resource.ProviderType)
				}

				var requestorAccount *RequestorAccount
				for _, ra := range requestorAccounts {
					if ra.ProviderType == resource.ProviderType && ra.AccountType == pkgAccountConfig.AccountType {
						requestorAccount = ra
						break
					}
				}
				if requestorAccount == nil {
					return nil, fmt.Errorf("unable to find requestor account for provider type %q and account type %q", resource.ProviderType, pkgAccountConfig.AccountType)
				}

				accountType := pkgAccountConfig.AccountType
				accountID := requestorAccount.AccountID

				grantDep := &domain.Grant{
					ResourceID:  resource.ID,
					AccountType: accountType,
					AccountID:   accountID,
					Role:        pkgAccountConfig.GrantParameters.Role,

					IsPermanent:          pkgGrant.IsPermanent,
					ExpirationDate:       pkgGrant.ExpirationDate,
					ExpirationDateReason: pkgGrant.ExpirationDateReason,

					GroupID:   pkgResource.ID,
					GroupType: groupTypePackageUser,
				}

				dependencies = append(dependencies, grantDep)
			}
		}
	}

	return dependencies, nil
}

func (p *provider) getGrantableResources(ctx context.Context, packageID string) ([]*domain.Resource, error) {
	return p.resourceService.Find(ctx, domain.ListResourcesFilter{
		GroupIDs:   []string{packageID},
		GroupTypes: []string{groupTypePackageResource},
	})
}

func getPackageInfo(r *domain.Resource) (*PackageInfo, error) {
	if r == nil {
		return nil, errors.New("resource can't be nil")
	}

	if r.Details == nil {
		return nil, errors.New("empty package details")
	}

	var pi PackageInfo
	if err := mapstructure.Decode(r.Details, &pi); err != nil {
		return nil, err
	}

	return &pi, nil
}

func getRequestorAccounts(a *domain.Appeal) ([]*RequestorAccount, error) {
	if a == nil {
		return nil, errors.New("appeal can't be nil")
	}

	appealParams, ok := a.Details[domain.ReservedDetailsKeyProviderParameters].(map[string]any)
	if !ok || appealParams == nil {
		return nil, errors.New("invalid appeal parameters value, expected: map[string]any")
	}

	key := providerParameterKeyAccounts
	value, ok := appealParams[key]
	if !ok {
		return nil, fmt.Errorf("couldn't find %q in appeal parameters", key)
	}
	var requestorAccounts []*RequestorAccount
	if err := mapstructure.Decode(value, &requestorAccounts); err != nil {
		return nil, fmt.Errorf("failed to parse %q parameter: %w", key, err)
	}

	return requestorAccounts, nil
}

func getUniqueProviderTypes(resources []*domain.Resource) []string {
	providerTypeSet := make(map[string]struct{})
	for _, r := range resources {
		providerTypeSet[r.ProviderType] = struct{}{}
	}

	providerTypes := make([]string, 0, len(providerTypeSet))
	for pt := range providerTypeSet {
		providerTypes = append(providerTypes, pt)
	}
	return providerTypes
}
