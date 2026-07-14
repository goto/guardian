package alicloud_sso

import (
	"context"
	"fmt"
	"strings"
	"sync"

	sso "github.com/alibabacloud-go/cloudsso-20210515/client"

	pv "github.com/goto/guardian/core/provider"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/aliclientmanager"
	"github.com/goto/guardian/pkg/log"
)

//go:generate mockery --name=encryptor --exported --with-expecter
type encryptor interface {
	domain.Crypto
}

//go:generate mockery --name=ssoClient --exported --with-expecter
type ssoClient interface {
	ListGroups(request *sso.ListGroupsRequest) (*sso.ListGroupsResponse, error)
	AddUserToGroup(request *sso.AddUserToGroupRequest) (*sso.AddUserToGroupResponse, error)
	RemoveUserFromGroup(request *sso.RemoveUserFromGroupRequest) (*sso.RemoveUserFromGroupResponse, error)

	ListAccessConfigurations(request *sso.ListAccessConfigurationsRequest) (*sso.ListAccessConfigurationsResponse, error)
	AddPermissionPolicyToAccessConfiguration(request *sso.AddPermissionPolicyToAccessConfigurationRequest) (*sso.AddPermissionPolicyToAccessConfigurationResponse, error)
	RemovePermissionPolicyFromAccessConfiguration(request *sso.RemovePermissionPolicyFromAccessConfigurationRequest) (*sso.RemovePermissionPolicyFromAccessConfigurationResponse, error)
	ProvisionAccessConfiguration(request *sso.ProvisionAccessConfigurationRequest) (*sso.ProvisionAccessConfigurationResponse, error)
	GetTaskStatus(request *sso.GetTaskStatusRequest) (*sso.GetTaskStatusResponse, error)
	ListAccessConfigurationProvisionings(request *sso.ListAccessConfigurationProvisioningsRequest) (*sso.ListAccessConfigurationProvisioningsResponse, error)
}

type provider struct {
	pv.UnimplementedClient
	pv.PermissionManager
	typeName  string
	encryptor encryptor
	logger    log.Logger
	mu        *sync.Mutex

	ssoClientsCache map[string]*aliclientmanager.Manager[*sso.Client]

	// testSSOClient, when set, overrides the CloudSSO client returned by
	// getSSOClient. It is only used to inject a mock in tests.
	testSSOClient ssoClient
}

func NewProvider(
	typeName string,
	encryptor encryptor,
	logger log.Logger,
) *provider {
	return &provider{
		typeName:        typeName,
		encryptor:       encryptor,
		logger:          logger,
		mu:              &sync.Mutex{},
		ssoClientsCache: make(map[string]*aliclientmanager.Manager[*sso.Client]),
	}
}

func (p *provider) GetType() string {
	return p.typeName
}

func (p *provider) GetAccountTypes() []string {
	return []string{accountTypeSSOUser}
}

func (p *provider) GetRoles(pc *domain.ProviderConfig, resourceType string) ([]*domain.Role, error) {
	return pv.GetRoles(pc, resourceType)
}

func (p *provider) CreateConfig(pc *domain.ProviderConfig) error {
	cfg := &config{pc}
	if err := cfg.validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	// encrypt sensitive config
	creds, err := cfg.getCredentials()
	if err != nil {
		return err
	}
	if err := creds.encrypt(p.encryptor); err != nil {
		return fmt.Errorf("failed to encrypt credentials: %w", err)
	}
	pc.Credentials = creds

	return nil
}

func (p *provider) ValidateResourceIdentifiers(ctx context.Context, r *domain.Resource) error {
	if r.Type != resourceTypeGroup && r.Type != resourceTypeAccessConfiguration {
		return fmt.Errorf("only resource types %q and %q are supported for provider type %q", resourceTypeGroup, resourceTypeAccessConfiguration, sourceName)
	}
	if r.URN == "" {
		return fmt.Errorf("resource urn is required")
	}

	return nil
}

func (p *provider) ValidateResourceDetails(ctx context.Context, r *domain.Resource) error {
	return nil
}

func (p *provider) GetResources(ctx context.Context, pc *domain.ProviderConfig) ([]*domain.Resource, error) {
	var resources = make([]*domain.Resource, 0)
	var availableResourceTypes = pc.GetResourceTypes()

	for _, resourceType := range availableResourceTypes {
		switch resourceType {
		case resourceTypeGroup:
			groups, err := p.getGroups(ctx, pc)
			if err != nil {
				return nil, err
			}
			resources = append(resources, groups...)
		case resourceTypeAccessConfiguration:
			accessConfigs, err := p.getAccessConfigurations(ctx, pc)
			if err != nil {
				return nil, err
			}
			resources = append(resources, accessConfigs...)
		}
	}

	return resources, nil
}

func (p *provider) GrantAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	switch g.Resource.Type {
	case resourceTypeGroup:
		if err := p.addMemberToGroup(ctx, pc, g); err != nil {
			return err
		}

	case resourceTypeAccessConfiguration:
		if err := p.addSystemPoliciesToAccessConfig(ctx, pc, g); err != nil {
			return err
		}

	default:
		return fmt.Errorf("unsupported resource type: %s", g.Resource.Type)
	}

	return nil
}

func (p *provider) RevokeAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	switch g.Resource.Type {
	case resourceTypeGroup:
		if err := p.removeMemberFromGroup(ctx, pc, g); err != nil &&
			!strings.Contains(strings.ToLower(err.Error()), strings.ToLower("EntityNotExists.GroupMember")) {
			return err
		}

	case resourceTypeAccessConfiguration:
		if err := p.removeSystemPoliciesFromAccessConfig(ctx, pc, g); err != nil {
			return err
		}

	default:
		return fmt.Errorf("unsupported resource type: %s", g.Resource.Type)
	}

	return nil
}

func (p *provider) getCreds(pc *domain.ProviderConfig) (*credentials, error) {
	cfg := &config{pc}
	creds, err := cfg.getCredentials()
	if err != nil {
		return nil, err
	}
	if err := creds.decrypt(p.encryptor); err != nil {
		return nil, fmt.Errorf("failed to decrypt credentials: %w", err)
	}
	return creds, nil
}
