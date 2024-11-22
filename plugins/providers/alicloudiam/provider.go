package alicloudiam

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	ram "github.com/alibabacloud-go/ram-20150501/v2/client"
	"github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/utils"
	"github.com/mitchellh/mapstructure"
)

//go:generate mockery --name=AliCloudIamClient --exported --with-expecter
type AliCloudIamClient interface {
	GrantAccess(ctx context.Context, policyName, policyType, username string) error
	RevokeAccess(ctx context.Context, policyName, policyType, username string) error
	GrantAccessToRole(ctx context.Context, policyName, policyType, roleName string) error
	RevokeAccessFromRole(ctx context.Context, policyName, policyType, roleName string) error
	ListAccess(ctx context.Context, pc domain.ProviderConfig, resources []*domain.Resource) (domain.MapResourceAccess, error)
	GetAllPoliciesByType(_ context.Context, policyType string, maxItems int32) ([]*ram.ListPoliciesResponseBodyPoliciesPolicy, error)
}

//go:generate mockery --name=encryptor --exported --with-expecter
type encryptor interface {
	domain.Crypto
}

type Provider struct {
	provider.PermissionManager

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
	ctx := context.Background()

	c := NewConfig(pc, p.crypto)
	if err := c.ParseAndValidate(); err != nil {
		return err
	}

	client, err := p.getIamClient(pc)
	if err != nil {
		return err
	}

	for _, r := range c.ProviderConfig.Resources {
		if err = c.validatePermissions(ctx, r, client); err != nil {
			return err
		}
	}

	return c.EncryptCredentials()
}

func (p *Provider) GetResources(_ context.Context, pc *domain.ProviderConfig) ([]*domain.Resource, error) {
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
	client, err := p.getIamClient(pc)
	if err != nil {
		return err
	}

	permissions, err := getListPermissionsFromGrant(pc, g)
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
			for _, permission := range permissions {
				err = client.GrantAccess(ctx, permission.Name, permission.Type, username)
				if err != nil && !errors.Is(err, ErrPermissionAlreadyExists) {
					return err
				}
			}
			return nil

		case AccountTypeRamRole:
			for _, permission := range permissions {
				err = client.GrantAccessToRole(ctx, permission.Name, permission.Type, g.AccountID)
				if err != nil && !errors.Is(err, ErrPermissionAlreadyExists) {
					return err
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
	client, err := p.getIamClient(pc)
	if err != nil {
		return err
	}

	permissions, err := getListPermissionsFromGrant(pc, g)
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
			for _, permission := range permissions {
				err = client.RevokeAccess(ctx, permission.Name, permission.Type, username)
				if err != nil && !errors.Is(err, ErrPermissionNotExist) {
					return err
				}
			}
			return nil

		case AccountTypeRamRole:
			for _, permission := range permissions {
				err = client.RevokeAccessFromRole(ctx, permission.Name, permission.Type, g.AccountID)
				if err != nil && !errors.Is(err, ErrPermissionNotExist) {
					return err
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
	return getAccountTypes()
}

func (p *Provider) ListAccess(ctx context.Context, pc domain.ProviderConfig, resources []*domain.Resource) (domain.MapResourceAccess, error) {
	client, err := p.getIamClient(&pc)
	if err != nil {
		return nil, err
	}

	return client.ListAccess(ctx, pc, resources)
}

func (p *Provider) getIamClient(pc *domain.ProviderConfig) (AliCloudIamClient, error) {
	var credentials Credentials
	err := mapstructure.Decode(pc.Credentials, &credentials)
	if err != nil {
		return nil, err
	}
	providerURN := pc.URN

	if p.Clients[providerURN] != nil {
		return p.Clients[providerURN], nil
	}

	_ = credentials.Decrypt(p.crypto)
	client, err := NewIamClient(credentials.AccessKeyID, credentials.AccessKeySecret, credentials.ResourceName, credentials.RoleToAssume)
	if err != nil {
		return nil, err
	}

	p.Clients[providerURN] = client
	return client, nil
}

func getListPermissionsFromGrant(pc *domain.ProviderConfig, g domain.Grant) ([]*Permission, error) {
	if g.Resource == nil {
		return nil, errors.New("grant resource is nil")
	}

	var selectedResource *domain.ResourceConfig
	for _, r := range pc.Resources {
		if r.Type == g.Resource.Type {
			selectedResource = r
			break
		}
	}
	if selectedResource == nil {
		return nil, fmt.Errorf("resource with type '%v' at resource id '%v' does not exist", g.Resource.Type, g.ResourceID)
	}

	var selectedRole *domain.Role
	for _, r := range selectedResource.Roles {
		if r.ID == g.Role {
			selectedRole = r
			break
		}
	}
	if selectedRole == nil {
		return nil, fmt.Errorf("role '%v' at resource with id '%v' does not exist", g.Role, g.ResourceID)
	}

	permissions := make([]*Permission, len(selectedRole.Permissions))
	for i, rawPerm := range selectedRole.Permissions {
		if err := mapstructure.Decode(rawPerm, &permissions[i]); err != nil {
			return nil, err
		}
	}

	return permissions, nil
}

func getAccountTypes() []string {
	return []string{
		AccountTypeRamUser,
		AccountTypeRamRole,
	}
}

func getPolicyTypes() []string {
	return []string{
		PolicyTypeSystem,
		PolicyTypeCustom,
	}
}

func getResourceTypes() []string {
	return []string{
		ResourceTypeAccount,
	}
}

// splitAliAccountUserId splits an Alibaba Cloud account user ID into username and account ID.
// Example input: "foo.bar@12345679.onaliyun.com"
// Returns: username ("foo.bar"), accountId ("12345679"), or an error if the format is invalid.
func splitAliAccountUserId(d string) (string, string, error) {
	matched, _ := regexp.MatchString(aliAccountUserIdPattern, d)
	if !matched {
		return "", "", ErrInvalidAliAccountUserID
	}

	accountUserIDSplit := strings.Split(d, "@")
	username := accountUserIDSplit[0]
	accountId := strings.TrimSuffix(accountUserIDSplit[1], aliAccountUserIdDomainSuffix)

	return username, accountId, nil
}
