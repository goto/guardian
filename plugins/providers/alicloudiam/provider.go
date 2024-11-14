package alicloudiam

import (
	"errors"
	"fmt"
	"github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/utils"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/net/context"
	"regexp"
	"strings"
)

//go:generate mockery --name=GcloudIamClient --exported --with-expecter
type AliCloudIamClient interface {
	GrantAccess(ctx context.Context, policyName, policyType, username string) error
	RevokeAccess(ctx context.Context, policyName, policyType, username string) error
	GrantAccessToRole(ctx context.Context, policyName, policyType, roleName string) error
	RevokeAccessFromRole(ctx context.Context, policyName, policyType, roleName string) error
}

//go:generate mockery --name=encryptor --exported --with-expecter
type encryptor interface {
	domain.Crypto
}

type Provider struct {
	provider.PermissionManager
	provider.UnimplementedClient

	typeName string
	Clients  map[string]AliCloudIamClient
	crypto   encryptor
	logger   log.Logger
}

func NewProvider(typeName string, crypto encryptor, logger log.Logger) *Provider {
	return &Provider{
		typeName: typeName,
		Clients:  map[string]AliCloudIamClient{},
		crypto:   crypto,
		logger:   logger,
	}
}

func (p *Provider) GetType() string {
	return p.typeName
}

func (p *Provider) CreateConfig(pc *domain.ProviderConfig) error {
	c := NewConfig(pc, p.crypto)

	if err := c.ParseAndValidate(); err != nil {
		return err
	}

	client, err := p.getIamClient(pc)
	if err != nil {
		return err
	}

	for _, r := range c.ProviderConfig.Resources {
		if err = c.validatePermissions(r, client); err != nil {
			return err
		}
	}

	return c.EncryptCredentials()
}

func (p *Provider) GetResources(ctx context.Context, pc *domain.ProviderConfig) ([]*domain.Resource, error) {
	resources := make([]*domain.Resource, len(pc.Resources))
	for i, rc := range pc.Resources {
		switch rc.Type {
		case ResourceTypeAccount:
			var creds Credentials
			if err := mapstructure.Decode(pc.Credentials, &creds); err != nil {
				return nil, err
			}
			resources[i] = &domain.Resource{
				ProviderType: pc.Type,
				ProviderURN:  pc.URN,
				Type:         rc.Type,
				URN:          creds.ResourceName,
				Name:         fmt.Sprintf("%s - AliCloud IAM", creds.ResourceName),
				GlobalURN:    utils.GetGlobalURN("alicloudiam", pc.URN, rc.Type, creds.ResourceName),
			}

		default:
			return nil, ErrInvalidResourceType
		}
	}

	return resources, nil
}

func (p *Provider) GrantAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	var creds Credentials
	if err := mapstructure.Decode(pc.Credentials, &creds); err != nil {
		return err
	}

	client, err := p.getIamClient(pc)
	if err != nil {
		return err
	}

	switch g.Resource.Type {
	case ResourceTypeAccount:
		switch g.AccountType {
		case AccountTypeRamUser:
			username, _, err := splitAliAccountUserId(g.AccountID)
			if err != nil {
				return err
			}
			for _, perm := range g.Permissions {
				// Attempt to grant access with PolicyTypeSystem
				if err = client.GrantAccess(ctx, perm, PolicyTypeSystem, username); err != nil {
					if errors.Is(err, ErrPermissionAlreadyExists) {
						continue
					}
					// Try granting with PolicyTypeCustom if PolicyTypeSystem fails
					if err = client.GrantAccess(ctx, perm, PolicyTypeCustom, username); err != nil && !errors.Is(err, ErrPermissionAlreadyExists) {
						return err
					}
				}
			}
			return nil

		case AccountTypeRamRole:
			for _, perm := range g.Permissions {
				// Attempt to grant access with PolicyTypeSystem
				if err = client.GrantAccessToRole(ctx, perm, PolicyTypeSystem, g.AccountID); err != nil {
					if errors.Is(err, ErrPermissionAlreadyExists) {
						continue
					}
					// Try granting with PolicyTypeCustom if PolicyTypeSystem fails
					if err = client.GrantAccessToRole(ctx, perm, PolicyTypeCustom, g.AccountID); err != nil && !errors.Is(err, ErrPermissionAlreadyExists) {
						return err
					}
				}
			}
			return nil

		default:
			return ErrInvalidAccountType
		}

	default:
		return ErrInvalidResourceType
	}
}

func (p *Provider) RevokeAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	var creds Credentials
	if err := mapstructure.Decode(pc.Credentials, &creds); err != nil {
		return err
	}

	client, err := p.getIamClient(pc)
	if err != nil {
		return err
	}

	switch g.Resource.Type {
	case ResourceTypeAccount:
		switch g.AccountType {
		case AccountTypeRamUser:
			username, _, err := splitAliAccountUserId(g.AccountID)
			if err != nil {
				return err
			}
			for _, perm := range g.Permissions {
				// Attempt to revoke access with PolicyTypeSystem
				if errPolicyTypeSystem := client.RevokeAccess(ctx, perm, PolicyTypeSystem, username); errPolicyTypeSystem != nil {
					// Try revoking access with PolicyTypeCustom if PolicyTypeSystem fails
					if errPolicyTypeCustom := client.RevokeAccess(ctx, perm, PolicyTypeCustom, username); errPolicyTypeCustom != nil {
						if errors.Is(errPolicyTypeSystem, ErrPermissionNotExist) || errors.Is(errPolicyTypeSystem, ErrPermissionNotExist) {
							continue
						}
						// Return default system type error
						return errPolicyTypeSystem
					}
				}
			}
			return nil

		case AccountTypeRamRole:
			for _, perm := range g.Permissions {
				// Attempt to revoke access with PolicyTypeSystem
				if errPolicyTypeSystem := client.RevokeAccessFromRole(ctx, perm, PolicyTypeSystem, g.AccountID); errPolicyTypeSystem != nil {
					// Try revoking access with PolicyTypeCustom if PolicyTypeSystem fails
					if errPolicyTypeCustom := client.RevokeAccessFromRole(ctx, perm, PolicyTypeCustom, g.AccountID); errPolicyTypeCustom != nil {
						if errors.Is(errPolicyTypeSystem, ErrPermissionNotExist) || errors.Is(errPolicyTypeSystem, ErrPermissionNotExist) {
							continue
						}
						// Return default system type error
						return errPolicyTypeSystem
					}
				}
			}
			return nil

		default:
			return ErrInvalidAccountType
		}

	default:
		return ErrInvalidResourceType
	}
}

func (p *Provider) GetRoles(pc *domain.ProviderConfig, resourceType string) ([]*domain.Role, error) {
	return provider.GetRoles(pc, resourceType)
}

func (p *Provider) GetPermissions(_pc *domain.ProviderConfig, _resourceType, role string) ([]interface{}, error) {
	return p.PermissionManager.GetPermissions(_pc, _resourceType, role)
}

func (p *Provider) GetAccountTypes() []string {
	return []string{
		AccountTypeRamUser,
		AccountTypeRamRole,
	}
}

func (p *Provider) ListAccess(ctx context.Context, pc domain.ProviderConfig, resources []*domain.Resource) (domain.MapResourceAccess, error) {
	// TODO: implement this function
	return nil, errors.New("(p *Provider) ListAccess: not implemented")
}

func (p *Provider) getIamClient(pc *domain.ProviderConfig) (AliCloudIamClient, error) {
	var credentials Credentials
	if err := mapstructure.Decode(pc.Credentials, &credentials); err != nil {
		return nil, err
	}
	providerURN := pc.URN

	if p.Clients[providerURN] != nil {
		return p.Clients[providerURN], nil
	}

	credentials.Decrypt(p.crypto)
	client, err := newIamClient(credentials.AccessKeyID, credentials.AccessKeySecret, credentials.ResourceName)
	if err != nil {
		return nil, err
	}

	p.Clients[providerURN] = client
	return client, nil
}

// splitAliAccountUserId splits an Alibaba Cloud account user ID into username and account ID.
// Example input: "foo.bar@12345679.onaliyun.com"
// Returns: username ("foo.bar"), accountId ("12345679"), or an error if the format is invalid.
func splitAliAccountUserId(d string) (string, string, error) {
	const domainSuffix = ".onaliyun.com"
	const pattern = `^[a-zA-Z0-9._%+-]+@[0-9]+\.onaliyun\.com$`

	matched, _ := regexp.MatchString(pattern, d)
	if !matched {
		return "", "", ErrInvalidAliAccountUserID
	}

	accountUserIDSplit := strings.Split(d, "@")
	username := accountUserIDSplit[0]
	accountId := strings.TrimSuffix(accountUserIDSplit[1], domainSuffix)

	return username, accountId, nil
}
