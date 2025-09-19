package alicloud_sso

import (
	"context"
	"fmt"
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

type provider struct {
	pv.UnimplementedClient
	pv.PermissionManager
	typeName  string
	encryptor encryptor
	logger    log.Logger
	mu        *sync.Mutex

	ssoClientsCache map[string]*aliclientmanager.Manager[*sso.Client]
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
	if r.Type != resourceTypeGroup {
		return fmt.Errorf("only resource type %q is supported for provider type %q", resourceTypeGroup, sourceName)
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

	default:
		return fmt.Errorf("unsupported resource type: %s", g.Resource.Type)
	}

	return nil
}

func (p *provider) RevokeAccess(ctx context.Context, pc *domain.ProviderConfig, g domain.Grant) error {
	switch g.Resource.Type {
	case resourceTypeGroup:
		if err := p.removeMemberFromGroup(ctx, pc, g); err != nil {
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
